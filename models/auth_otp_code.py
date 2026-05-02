from datetime import timedelta
import logging
import re
import secrets

from odoo import api, fields, models
from odoo.exceptions import AccessDenied, UserError
from odoo.tools.misc import hmac


_logger = logging.getLogger(__name__)


class AuthOtpCode(models.Model):
    _name = "auth.otp.code"
    _description = "Authentication OTP Code"
    _order = "expires_at desc, id desc"
    _rec_name = "user_id"

    user_id = fields.Many2one("res.users", required=True, index=True, ondelete="cascade")
    company_id = fields.Many2one(
        "res.company",
        related="user_id.company_id",
        store=True,
        readonly=True,
    )
    purpose = fields.Selection(
        [
            ("login", "Login"),
            ("password_reset", "Password Reset"),
            ("device_verification", "Device Verification"),
        ],
        default="login",
        required=True,
        index=True,
    )
    delivery_channel = fields.Selection(
        [
            ("email", "Email"),
            ("authenticator_app", "Authenticator App"),
        ],
        default="email",
        required=True,
    )
    code_hash = fields.Char(required=True, copy=False)
    expires_at = fields.Datetime(required=True, index=True)
    used_at = fields.Datetime(index=True)
    attempts = fields.Integer(default=0)
    ip_address = fields.Char(index=True)
    user_agent = fields.Text()
    is_valid = fields.Boolean(compute="_compute_is_valid")

    @api.depends("expires_at", "used_at")
    def _compute_is_valid(self):
        now = fields.Datetime.now()
        for otp in self:
            otp.is_valid = bool(not otp.used_at and otp.expires_at and otp.expires_at >= now)

    def action_mark_used(self):
        self.write({"used_at": fields.Datetime.now()})

    @api.model
    def _esa_generate_code(self):
        return "%06d" % secrets.randbelow(1000000)

    @api.model
    def _esa_normalize_code(self, code):
        code = re.sub(r"\s+", "", str(code or ""))
        if not re.fullmatch(r"\d{6}", code):
            return False
        return code

    @api.model
    def _esa_hash_code(self, user, purpose, code, expires_at):
        return hmac(
            self.env(su=True),
            "enterprise_security_authentication.otp",
            (
                user.id,
                purpose,
                code,
                fields.Datetime.to_string(expires_at),
            ),
        )

    def _esa_is_usable(self, config):
        self.ensure_one()
        max_attempts = config.otp_max_attempts if config else 3
        return bool(
            not self.used_at
            and self.expires_at
            and self.expires_at >= fields.Datetime.now()
            and self.attempts < max_attempts
        )

    @api.model
    def _esa_create_email_login_otp(self, user, config, request_values):
        user.ensure_one()
        if not user.email:
            raise UserError(
                "No email address is configured for this account. Please contact your administrator."
            )

        template = self.env.ref(
            "enterprise_security_authentication.mail_template_security_email_otp",
            raise_if_not_found=False,
        )
        if not template:
            raise UserError("The email OTP template is missing. Please update the security module.")

        now = fields.Datetime.now()
        expires_at = now + timedelta(minutes=config.otp_expiration_minutes)
        code = self._esa_generate_code()

        self.sudo().search(
            [
                ("user_id", "=", user.id),
                ("purpose", "=", "login"),
                ("delivery_channel", "=", "email"),
                ("used_at", "=", False),
            ]
        ).write({"used_at": now})

        otp = self.sudo().create(
            {
                "user_id": user.id,
                "purpose": "login",
                "delivery_channel": "email",
                "code_hash": self._esa_hash_code(user, "login", code, expires_at),
                "expires_at": expires_at,
                "ip_address": request_values.get("ip_address"),
                "user_agent": request_values.get("user_agent"),
            }
        )

        try:
            template.sudo().with_context(
                otp_code=code,
                expiration_minutes=config.otp_expiration_minutes,
                ip_address=request_values.get("ip_address"),
                device_name=request_values.get("device_name"),
                location=request_values.get("location"),
            ).send_mail(
                user.id,
                force_send=True,
                raise_exception=True,
                email_layout_xmlid="mail.mail_notification_light",
            )
        except Exception as error:
            otp.unlink()
            _logger.exception("Could not send email OTP for user %s", user.login)
            raise UserError(
                "Could not send the verification code. Please contact your administrator."
            ) from error

        self.env["auth.audit.log"].log_event(
            "otp_sent",
            user=user,
            severity="info",
            description="Email OTP sent for login verification",
            ip_address=request_values.get("ip_address"),
            user_agent=request_values.get("user_agent"),
        )
        return otp

    def _esa_check_login_code(self, code, config):
        self.ensure_one()
        normalized_code = self._esa_normalize_code(code)
        if not normalized_code:
            self.write({"attempts": self.attempts + 1})
            raise AccessDenied("Invalid verification code format.")

        if not self._esa_is_usable(config):
            raise AccessDenied("The verification code is expired or no longer valid.")

        expected_hash = self._esa_hash_code(
            self.user_id,
            self.purpose,
            normalized_code,
            self.expires_at,
        )
        if not secrets.compare_digest(self.code_hash or "", expected_hash):
            self.write({"attempts": self.attempts + 1})
            raise AccessDenied("Verification failed. Please double-check the 6-digit code.")

        self.write({"used_at": fields.Datetime.now()})
        return True

    @api.model
    def _cron_cleanup_expired_codes(self):
        cutoff = fields.Datetime.now() - timedelta(days=1)
        self.sudo().search(
            [
                "|",
                ("expires_at", "<", cutoff),
                ("used_at", "<", cutoff),
            ]
        ).unlink()
