from datetime import timedelta
from hashlib import sha256
import logging

from odoo import api, fields, models
from odoo.http import request


_logger = logging.getLogger(__name__)


class AuthUserSession(models.Model):
    _name = "auth.user.session"
    _description = "User Session"
    _order = "last_activity_at desc, login_at desc, id desc"

    display_name = fields.Char(compute="_compute_display_name", store=True)
    user_id = fields.Many2one("res.users", required=True, index=True, ondelete="cascade")
    company_id = fields.Many2one(
        "res.company",
        related="user_id.company_id",
        store=True,
        readonly=True,
    )
    session_token = fields.Char(string="Session Token Hash", index=True, copy=False)
    ip_address = fields.Char(index=True)
    user_agent = fields.Text()
    device_name = fields.Char()
    location = fields.Char()
    login_at = fields.Datetime(default=fields.Datetime.now, required=True, index=True)
    last_activity_at = fields.Datetime(default=fields.Datetime.now, required=True, index=True)
    logout_at = fields.Datetime(index=True)
    active = fields.Boolean(default=True, index=True)
    terminated_by_id = fields.Many2one("res.users", readonly=True, ondelete="set null")
    termination_reason = fields.Char(readonly=True)

    @api.depends("user_id", "device_name", "ip_address", "login_at")
    def _compute_display_name(self):
        for session in self:
            parts = [session.user_id.name or "Unknown User"]
            if session.device_name:
                parts.append(session.device_name)
            elif session.ip_address:
                parts.append(session.ip_address)
            session.display_name = " - ".join(parts)

    def action_terminate(self):
        now = fields.Datetime.now()
        self.write(
            {
                "active": False,
                "logout_at": now,
                "terminated_by_id": self.env.user.id,
                "termination_reason": "Manual termination",
            }
        )
        for session in self:
            self.env["auth.audit.log"].log_event(
                "session_terminated",
                user=session.user_id,
                severity="warning",
                description="Session manually terminated",
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )

    @api.model
    def _hash_session_sid(self, sid):
        if not sid:
            return False
        return sha256(str(sid).encode()).hexdigest()

    @api.model
    def _sync_current_session(self):
        if not request or not request.session or not request.session.uid:
            return False

        config = self.env["auth.security.config"].sudo().get_active_config()
        if not config or not config.enable_session_tracking:
            return False

        token = self._hash_session_sid(request.session.sid)
        if not token:
            return False

        request_values = self.env["res.users"]._esa_request_values({})
        now = fields.Datetime.now()
        user = self.env["res.users"].sudo().browse(request.session.uid)

        session = self.sudo().search(
            [("session_token", "=", token), ("active", "=", True)],
            limit=1,
        )
        if session and session.user_id != user:
            session.write(
                {
                    "active": False,
                    "logout_at": now,
                    "termination_reason": "Session user changed",
                }
            )
            session = self.browse()

        values = {
            "user_id": user.id,
            "ip_address": request_values.get("ip_address"),
            "user_agent": request_values.get("user_agent"),
            "device_name": request_values.get("device_name"),
            "location": request_values.get("location"),
            "last_activity_at": now,
        }
        if session:
            session.write(values)
            return session

        values.update(
            {
                "session_token": token,
                "login_at": now,
                "active": True,
            }
        )
        session = self.sudo().create(values)
        self._send_login_notification(session, config)
        return session

    @api.model
    def _send_login_notification(self, session, config):
        if not config.send_login_notification or not session.user_id.email:
            return

        template = self.env.ref(
            "enterprise_security_authentication.mail_template_security_login_notification",
            raise_if_not_found=False,
        )
        if not template:
            return

        try:
            template.sudo().with_context(
                ip_address=session.ip_address,
                device_name=session.device_name,
                location=session.location,
                login_at=fields.Datetime.to_string(session.login_at),
            ).send_mail(session.user_id.id, force_send=False, email_layout_xmlid="mail.mail_notification_light")
        except Exception:
            _logger.exception("Could not queue login notification for user %s", session.user_id.login)

    @api.model
    def _close_current_session(self):
        if not request or not request.session:
            return False

        token = self._hash_session_sid(request.session.sid)
        if not token:
            return False

        sessions = self.sudo().search([("session_token", "=", token), ("active", "=", True)])
        if not sessions:
            return False

        now = fields.Datetime.now()
        sessions.write(
            {
                "active": False,
                "logout_at": now,
                "termination_reason": "User logout",
            }
        )
        for session in sessions:
            self.env["auth.audit.log"].log_event(
                "logout",
                user=session.user_id,
                severity="info",
                description="User logged out",
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )
        return True

    @api.model
    def _cron_close_expired_sessions(self):
        config = self.env["auth.security.config"].sudo().get_active_config()
        if not config or not config.enable_session_tracking:
            return

        cutoff = fields.Datetime.now() - timedelta(minutes=config.session_timeout_minutes)
        expired_sessions = self.sudo().search(
            [
                ("active", "=", True),
                ("last_activity_at", "<", cutoff),
            ]
        )
        expired_sessions.write(
            {
                "active": False,
                "logout_at": fields.Datetime.now(),
                "termination_reason": "Session timeout",
            }
        )
