from datetime import timedelta
from hashlib import sha256

from odoo import api, fields, models


class AuthSecurityTestWizard(models.TransientModel):
    _name = "auth.security.test.wizard"
    _description = "Security Test Console"

    user_id = fields.Many2one(
        "res.users",
        string="Test User",
        required=True,
        default=lambda self: self.env.user,
    )
    login = fields.Char(required=True, default=lambda self: self.env.user.login)
    ip_address = fields.Char(required=True, default="127.0.0.1")
    user_agent = fields.Text(default="Enterprise Security Test Console")
    device_name = fields.Char(default="Test Browser")
    location = fields.Char(default="Local Test")
    scenario = fields.Selection(
        [
            ("full", "Full Suite"),
            ("lockout", "Lockout Drill"),
            ("session", "Session Drill"),
            ("otp", "OTP Drill"),
            ("audit", "Audit Burst"),
        ],
        default="full",
        required=True,
    )
    failed_attempt_count = fields.Integer(default=3)
    mark_locked = fields.Boolean(default=True)
    otp_code = fields.Char(default="123456")
    notes = fields.Text(
        default=(
            "Generate sample security records, then check Monitoring and Configuration "
            "menus to confirm the backend UI is working."
        )
    )
    security_config_id = fields.Many2one(
        "auth.security.config",
        compute="_compute_security_config",
        string="Active Policy",
    )
    user_locked_until = fields.Datetime(related="user_id.esa_locked_until", readonly=True)
    is_user_locked = fields.Boolean(compute="_compute_dashboard")
    test_total_count = fields.Integer(compute="_compute_dashboard")
    test_login_attempt_count = fields.Integer(compute="_compute_dashboard")
    test_failed_attempt_count = fields.Integer(compute="_compute_dashboard")
    test_success_attempt_count = fields.Integer(compute="_compute_dashboard")
    test_active_session_count = fields.Integer(compute="_compute_dashboard")
    test_audit_log_count = fields.Integer(compute="_compute_dashboard")
    test_otp_code_count = fields.Integer(compute="_compute_dashboard")
    test_critical_log_count = fields.Integer(compute="_compute_dashboard")
    last_event_at = fields.Datetime(compute="_compute_dashboard")
    last_event_type = fields.Char(compute="_compute_dashboard")

    @api.depends("user_id")
    def _compute_security_config(self):
        config = self.env["auth.security.config"].sudo().get_active_config()
        for wizard in self:
            wizard.security_config_id = config

    @api.depends("user_id", "login", "ip_address", "user_agent")
    def _compute_dashboard(self):
        marker = self._test_marker()
        login_attempt_model = self.env["auth.login.attempt"].sudo()
        session_model = self.env["auth.user.session"].sudo()
        audit_model = self.env["auth.audit.log"].sudo()
        otp_model = self.env["auth.otp.code"].sudo()

        for wizard in self:
            login = wizard._login()
            ip_address = wizard.ip_address
            user_agent = wizard.user_agent

            attempts = login_attempt_model.search(
                [
                    ("login", "=", login),
                    ("ip_address", "=", ip_address),
                ]
            )
            test_attempts = attempts.filtered(
                lambda attempt: (attempt.failure_reason and marker in attempt.failure_reason)
                or attempt.user_agent == user_agent
            )
            sessions = session_model.search(
                [
                    ("user_id", "=", wizard.user_id.id),
                    ("ip_address", "=", ip_address),
                    ("session_token", "ilike", "test-"),
                ]
            )
            audit_logs = audit_model.search(
                [
                    ("user_id", "=", wizard.user_id.id),
                    ("ip_address", "=", ip_address),
                    ("description", "ilike", marker),
                ]
            )
            otp_codes = otp_model.search(
                [
                    ("user_id", "=", wizard.user_id.id),
                    ("ip_address", "=", ip_address),
                    ("user_agent", "=", user_agent),
                ]
            )
            last_log = audit_logs[:1]

            wizard.test_login_attempt_count = len(test_attempts)
            wizard.test_failed_attempt_count = len(test_attempts.filtered(lambda attempt: not attempt.success))
            wizard.test_success_attempt_count = len(test_attempts.filtered("success"))
            wizard.test_active_session_count = len(sessions.filtered("active"))
            wizard.test_audit_log_count = len(audit_logs)
            wizard.test_otp_code_count = len(otp_codes)
            wizard.test_critical_log_count = len(audit_logs.filtered(lambda log: log.severity == "critical"))
            wizard.test_total_count = len(test_attempts) + len(sessions) + len(audit_logs) + len(otp_codes)
            wizard.last_event_at = last_log.event_at if last_log else False
            wizard.last_event_type = dict(audit_model._fields["event_type"].selection).get(
                last_log.event_type,
                "",
            ) if last_log else ""
            wizard.is_user_locked = bool(
                wizard.user_locked_until and wizard.user_locked_until > fields.Datetime.now()
            )

    @api.onchange("user_id")
    def _onchange_user_id(self):
        if self.user_id:
            self.login = self.user_id.login

    @api.onchange("scenario")
    def _onchange_scenario(self):
        config = self.env["auth.security.config"].sudo().get_active_config()
        max_failed_attempts = config.max_failed_attempts if config else 5
        if self.scenario == "lockout":
            self.failed_attempt_count = max(max_failed_attempts, 1)
            self.mark_locked = True
        elif self.scenario == "session":
            self.failed_attempt_count = 1
            self.mark_locked = False
        elif self.scenario == "otp":
            self.failed_attempt_count = 1
            self.mark_locked = False
        elif self.scenario == "audit":
            self.failed_attempt_count = 2
            self.mark_locked = True
        else:
            self.failed_attempt_count = max(3, max_failed_attempts)
            self.mark_locked = True

    def _notify(self, title, message, notification_type="success"):
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": title,
                "message": message,
                "sticky": False,
                "type": notification_type,
            },
        }

    def _test_marker(self):
        return "[TEST DATA]"

    def _login(self):
        return self.login or self.user_id.login or self.user_id.email

    def _base_record_domain(self):
        return [
            ("user_id", "=", self.user_id.id),
            ("ip_address", "=", self.ip_address),
        ]

    def _open_records(self, model, name, domain, context=None):
        return {
            "type": "ir.actions.act_window",
            "name": name,
            "res_model": model,
            "view_mode": "tree,form",
            "domain": domain,
            "context": context or {},
            "target": "current",
        }

    def action_generate_failed_attempts(self):
        self.ensure_one()
        now = fields.Datetime.now()
        count = max(self.failed_attempt_count, 1)
        values_list = []
        for index in range(count):
            values = {
                "login": self._login(),
                "user_id": self.user_id.id,
                "company_id": self.env.company.id,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
                "attempted_at": now - timedelta(minutes=count - index),
                "success": False,
                "failure_reason": "%s Invalid password from test console" % self._test_marker(),
            }
            if self.mark_locked and index == count - 1:
                values["locked_until"] = now + timedelta(minutes=30)
                values["failure_reason"] = "%s Account locked by test console" % self._test_marker()
            values_list.append(values)

        self.env["auth.login.attempt"].sudo().create(values_list)
        if self.mark_locked:
            self.user_id.sudo().write({"esa_locked_until": now + timedelta(minutes=30)})
            self.env["auth.audit.log"].log_event(
                "account_locked",
                user=self.user_id,
                severity="critical",
                description="%s Account locked by failed-attempt test" % self._test_marker(),
                ip_address=self.ip_address,
                user_agent=self.user_agent,
            )
        return self._notify("Test Data Created", "%s failed login attempts were generated." % count)

    def action_generate_successful_login(self):
        self.ensure_one()
        self.env["auth.login.attempt"].sudo().create(
            {
                "login": self._login(),
                "user_id": self.user_id.id,
                "company_id": self.env.company.id,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
                "success": True,
            }
        )
        self.env["auth.audit.log"].log_event(
            "login_success",
            user=self.user_id,
            severity="info",
            description="%s Successful login generated by test console" % self._test_marker(),
            ip_address=self.ip_address,
            user_agent=self.user_agent,
        )
        return self._notify("Test Data Created", "A successful login and audit log were generated.")

    def action_create_active_session(self):
        self.ensure_one()
        token_seed = "%s-%s-%s" % (self.user_id.id, self.ip_address, fields.Datetime.now())
        self.env["auth.user.session"].sudo().create(
            {
                "user_id": self.user_id.id,
                "session_token": "test-%s" % sha256(token_seed.encode()).hexdigest()[:24],
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
                "device_name": self.device_name,
                "location": self.location,
                "active": True,
            }
        )
        return self._notify("Test Data Created", "An active user session was generated.")

    def action_create_audit_logs(self):
        self.ensure_one()
        audit_model = self.env["auth.audit.log"].sudo()
        events = [
            ("login_failure", "warning", "Failed login generated by test console"),
            ("account_locked", "critical", "Account lock generated by test console"),
            ("password_reset_requested", "info", "Password reset audit generated by test console"),
            ("ip_restricted", "warning", "IP restriction event generated by test console"),
        ]
        for event_type, severity, description in events:
            audit_model.log_event(
                event_type,
                user=self.user_id,
                severity=severity,
                description="%s %s" % (self._test_marker(), description),
                ip_address=self.ip_address,
                user_agent=self.user_agent,
            )
        return self._notify("Test Data Created", "%s audit log events were generated." % len(events))

    def action_create_otp_code(self):
        self.ensure_one()
        code = self.otp_code or "123456"
        self.env["auth.otp.code"].sudo().create(
            {
                "user_id": self.user_id.id,
                "purpose": "login",
                "delivery_channel": "email",
                "code_hash": sha256(code.encode()).hexdigest(),
                "expires_at": fields.Datetime.now() + timedelta(minutes=10),
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
            }
        )
        self.env["auth.audit.log"].log_event(
            "otp_sent",
            user=self.user_id,
            severity="info",
            description="%s Email OTP generated by test console" % self._test_marker(),
            ip_address=self.ip_address,
            user_agent=self.user_agent,
        )
        return self._notify("Test Data Created", "An email OTP record was generated.")

    def action_generate_all(self):
        self.ensure_one()
        self.action_generate_failed_attempts()
        self.action_generate_successful_login()
        self.action_create_active_session()
        self.action_create_audit_logs()
        self.action_create_otp_code()
        return self._notify("Test Data Created", "Full security test dataset generated.")

    def action_run_selected_scenario(self):
        self.ensure_one()
        if self.scenario == "lockout":
            return self.action_run_lockout_drill()
        if self.scenario == "session":
            self.action_create_active_session()
            return self._notify("Scenario Complete", "Session drill generated an active session.")
        if self.scenario == "otp":
            self.action_create_otp_code()
            return self._notify("Scenario Complete", "OTP drill generated an email OTP.")
        if self.scenario == "audit":
            self.action_create_audit_logs()
            return self._notify("Scenario Complete", "Audit burst generated security events.")
        return self.action_generate_all()

    def action_run_lockout_drill(self):
        self.ensure_one()
        config = self.env["auth.security.config"].sudo().get_active_config()
        if config:
            self.failed_attempt_count = max(config.max_failed_attempts, 1)
        self.mark_locked = True
        self.action_generate_failed_attempts()
        return self._notify("Scenario Complete", "Lockout drill generated failures and locked the test user.")

    def action_unlock_test_user(self):
        self.ensure_one()
        self.user_id.sudo().write({"esa_locked_until": False})
        self.env["auth.audit.log"].log_event(
            "settings_changed",
            user=self.user_id,
            severity="info",
            description="%s Test user unlocked from console" % self._test_marker(),
            ip_address=self.ip_address,
            user_agent=self.user_agent,
        )
        return self._notify("User Unlocked", "The selected test user is unlocked.")

    def action_open_login_attempts(self):
        self.ensure_one()
        return self._open_records(
            "auth.login.attempt",
            "Test Login Attempts",
            [
                ("login", "=", self._login()),
                ("ip_address", "=", self.ip_address),
            ],
        )

    def action_open_sessions(self):
        self.ensure_one()
        return self._open_records(
            "auth.user.session",
            "Test Sessions",
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
            ],
            {"search_default_active_sessions": 1},
        )

    def action_open_audit_logs(self):
        self.ensure_one()
        return self._open_records(
            "auth.audit.log",
            "Test Audit Logs",
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
            ],
        )

    def action_open_otp_codes(self):
        self.ensure_one()
        return self._open_records(
            "auth.otp.code",
            "Test OTP Codes",
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
            ],
        )

    def action_open_security_policy(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Security Policy",
            "res_model": "auth.security.config",
            "view_mode": "form",
            "res_id": self.security_config_id.id,
            "target": "current",
        }

    def action_clear_test_data(self):
        self.ensure_one()
        marker = self._test_marker()
        login = self._login()
        self.env["auth.login.attempt"].sudo().search(
            [
                ("login", "=", login),
                ("ip_address", "=", self.ip_address),
                ("failure_reason", "ilike", marker),
            ]
        ).unlink()
        self.env["auth.login.attempt"].sudo().search(
            [
                ("login", "=", login),
                ("ip_address", "=", self.ip_address),
                ("success", "=", True),
                ("user_agent", "=", self.user_agent),
            ]
        ).unlink()
        self.env["auth.user.session"].sudo().search(
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
                ("session_token", "ilike", "test-"),
            ]
        ).unlink()
        self.env["auth.audit.log"].sudo().search(
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
                ("description", "ilike", marker),
            ]
        ).unlink()
        self.env["auth.otp.code"].sudo().search(
            [
                ("user_id", "=", self.user_id.id),
                ("ip_address", "=", self.ip_address),
                ("user_agent", "=", self.user_agent),
            ]
        ).unlink()
        self.user_id.sudo().write({"esa_locked_until": False})
        return self._notify("Test Data Cleared", "Generated records for this user and IP were removed.")
