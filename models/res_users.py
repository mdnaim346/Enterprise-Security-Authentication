from datetime import timedelta
import ipaddress
import logging
import re

from odoo import api, fields, models, registry, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied, AccessError
from odoo.http import request


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    esa_locked_until = fields.Datetime(string="Security Lock Until", copy=False, readonly=True)

    def _esa_requires_email_otp(self, config=None):
        self.ensure_one()
        config = config or self.env["auth.security.config"].sudo().get_active_config()
        return bool(config and config.enable_email_otp)

    def _mfa_type(self):
        result = super()._mfa_type()
        if result is not None:
            return result
        if request and self._esa_requires_email_otp():
            return "esa_email_otp"

    def _mfa_url(self):
        result = super()._mfa_url()
        if result is not None:
            return result
        if self._mfa_type() == "esa_email_otp":
            return "/web/login/esa_otp"

    @classmethod
    def _login(cls, db, login, password, user_agent_env):
        cls._esa_precheck_login(db, login, user_agent_env)
        try:
            uid = super(ResUsers, cls)._login(db, login, password, user_agent_env=user_agent_env)
        except AccessDenied:
            try:
                cls._esa_record_login_failure(db, login, user_agent_env)
            except Exception:
                _logger.exception("Could not record failed login attempt for %s", login)
            raise

        try:
            cls._esa_record_login_success(db, uid, login, user_agent_env)
        except Exception:
            _logger.exception("Could not record successful login for %s", login)
        return uid

    @api.model
    def _esa_request_values(self, user_agent_env=None):
        user_agent_env = user_agent_env or {}
        ip_address = user_agent_env.get("REMOTE_ADDR") or "n/a"
        user_agent = user_agent_env.get("HTTP_USER_AGENT") or ""
        device_name = False
        location = False

        if request:
            ip_address = request.httprequest.environ.get("REMOTE_ADDR") or ip_address
            if request.httprequest.user_agent:
                user_agent = str(request.httprequest.user_agent)
                browser = request.httprequest.user_agent.browser
                platform = request.httprequest.user_agent.platform
                device_parts = [part.capitalize() for part in (browser, platform) if part]
                device_name = " / ".join(device_parts) if device_parts else False
            location = self._esa_request_location()

        return {
            "ip_address": ip_address,
            "user_agent": user_agent,
            "device_name": device_name,
            "location": location,
        }

    @api.model
    def _esa_request_location(self):
        if not request:
            return False
        city = request.geoip.get("city") or False
        region = request.geoip.get("region_name") or False
        country = request.geoip.get("country") or False
        return ", ".join(part for part in (city, region, country) if part) or False

    @api.model
    def _esa_ip_allowed(self, config, ip_address):
        raw_rules = config.allowed_ip_addresses or ""
        rules = [rule for rule in re.split(r"[\s,;]+", raw_rules.strip()) if rule]
        if not rules:
            return True

        try:
            current_ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        for rule in rules:
            try:
                if current_ip in ipaddress.ip_network(rule, strict=False):
                    return True
            except ValueError:
                if ip_address == rule:
                    return True
        return False

    @classmethod
    def _esa_precheck_login(cls, db, login, user_agent_env):
        with registry(db).cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            users = env[cls._name].sudo()
            config = env["auth.security.config"].sudo().get_active_config()
            if not config:
                return

            request_values = users._esa_request_values(user_agent_env)
            user = users.search(users._get_login_domain(login), order=users._get_login_order(), limit=1)
            now = fields.Datetime.now()

            if config.enable_ip_restriction and not users._esa_ip_allowed(config, request_values["ip_address"]):
                users._esa_create_login_attempt(
                    config,
                    login,
                    user,
                    False,
                    request_values,
                    _("IP address is not allowed"),
                )
                env["auth.audit.log"].log_event(
                    "ip_restricted",
                    user=user,
                    severity="warning",
                    description=_("Login blocked by IP restriction"),
                    ip_address=request_values["ip_address"],
                    user_agent=request_values["user_agent"],
                )
                cr.commit()
                raise AccessDenied(_("Login is not allowed from this IP address."))

            if user and config.enable_account_lock and user.esa_locked_until:
                if user.esa_locked_until > now:
                    users._esa_create_login_attempt(
                        config,
                        login,
                        user,
                        False,
                        request_values,
                        _("Account is locked"),
                        locked_until=user.esa_locked_until,
                    )
                    env["auth.audit.log"].log_event(
                        "access_denied",
                        user=user,
                        severity="warning",
                        description=_("Login blocked because account is temporarily locked"),
                        ip_address=request_values["ip_address"],
                        user_agent=request_values["user_agent"],
                    )
                    cr.commit()
                    raise AccessDenied(
                        _("Your account is temporarily locked. Please try again after %s.")
                        % fields.Datetime.to_string(user.esa_locked_until)
                    )
                user.write({"esa_locked_until": False})

    @classmethod
    def _esa_record_login_failure(cls, db, login, user_agent_env):
        with registry(db).cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            users = env[cls._name].sudo()
            config = env["auth.security.config"].sudo().get_active_config()
            if not config:
                return

            request_values = users._esa_request_values(user_agent_env)
            user = users.search(users._get_login_domain(login), order=users._get_login_order(), limit=1)
            now = fields.Datetime.now()
            locked_until = False
            failure_reason = _("Invalid login or password")
            severity = "warning"
            event_type = "login_failure"

            if user and config.enable_account_lock:
                failed_count = users._esa_recent_failed_attempt_count(user, login, config, now) + 1
                if failed_count >= config.max_failed_attempts:
                    locked_until = now + timedelta(minutes=config.lock_duration_minutes)
                    failure_reason = _("Account locked after too many failed login attempts")
                    user.write({"esa_locked_until": locked_until})
                    severity = "critical"
                    event_type = "account_locked"

            users._esa_create_login_attempt(
                config,
                login,
                user,
                False,
                request_values,
                failure_reason,
                locked_until=locked_until,
            )
            if config.track_user_activity:
                env["auth.audit.log"].log_event(
                    event_type,
                    user=user,
                    severity=severity,
                    description=failure_reason,
                    ip_address=request_values["ip_address"],
                    user_agent=request_values["user_agent"],
                )
            cr.commit()

    @classmethod
    def _esa_record_login_success(cls, db, uid, login, user_agent_env):
        user_agent_env = user_agent_env or {}
        with registry(db).cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            users = env[cls._name].sudo()
            config = env["auth.security.config"].sudo().get_active_config()
            if not config:
                return

            user = users.browse(uid)
            request_values = users._esa_request_values(user_agent_env)
            if user_agent_env.get("interactive", True) and user._esa_requires_email_otp(config):
                return
            if user.esa_locked_until:
                user.write({"esa_locked_until": False})
            users._esa_create_login_attempt(config, login, user, True, request_values)
            if config.track_user_activity:
                env["auth.audit.log"].log_event(
                    "login_success",
                    user=user,
                    severity="info",
                    description=_("User authenticated successfully"),
                    ip_address=request_values["ip_address"],
                    user_agent=request_values["user_agent"],
                )
            cr.commit()

    @api.model
    def _esa_create_login_attempt(
        self,
        config,
        login,
        user,
        success,
        request_values,
        failure_reason=False,
        locked_until=False,
    ):
        if not config.enable_login_attempt_tracking:
            return self.env["auth.login.attempt"].browse()

        return self.env["auth.login.attempt"].sudo().create(
            {
                "login": login or "",
                "user_id": user.id if user else False,
                "company_id": user.company_id.id if user and user.company_id else self.env.company.id,
                "ip_address": request_values.get("ip_address"),
                "user_agent": request_values.get("user_agent"),
                "success": success,
                "failure_reason": failure_reason,
                "locked_until": locked_until,
            }
        )

    @api.model
    def _esa_record_mfa_login_success(self, user, login, request_values, config=None):
        config = config or self.env["auth.security.config"].sudo().get_active_config()
        if not config:
            return

        user = user.sudo()
        if user.esa_locked_until:
            user.write({"esa_locked_until": False})

        self._esa_create_login_attempt(config, login, user, True, request_values)
        if config.track_user_activity:
            self.env["auth.audit.log"].log_event(
                "login_success",
                user=user,
                severity="info",
                description=_("User authenticated successfully"),
                ip_address=request_values.get("ip_address"),
                user_agent=request_values.get("user_agent"),
            )

    @api.model
    def _esa_recent_failed_attempt_count(self, user, login, config, now):
        cutoff = now - timedelta(minutes=config.lock_duration_minutes)
        domain = [
            ("success", "=", False),
            ("locked_until", "=", False),
            ("attempted_at", ">=", cutoff),
        ]
        if user:
            domain.append(("user_id", "=", user.id))
            success_domain = [("user_id", "=", user.id), ("success", "=", True)]
        else:
            domain.append(("login", "=", login or ""))
            success_domain = [("login", "=", login or ""), ("success", "=", True)]

        last_success = self.env["auth.login.attempt"].sudo().search(success_domain, limit=1)
        if last_success and last_success.attempted_at and last_success.attempted_at > cutoff:
            domain.append(("attempted_at", ">", last_success.attempted_at))
        return self.env["auth.login.attempt"].sudo().search_count(domain)

    def action_esa_unlock_account(self):
        if not (
            self.env.user.has_group("enterprise_security_authentication.group_security_manager")
            or self.env.user.has_group("base.group_system")
        ):
            raise AccessError(_("Only security managers can unlock accounts."))

        self.write({"esa_locked_until": False})
        for user in self:
            self.env["auth.audit.log"].log_event(
                "settings_changed",
                user=user,
                severity="info",
                description=_("Account security lock manually cleared"),
            )
        return True
