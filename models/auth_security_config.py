from odoo import api, fields, models, _
from odoo.exceptions import ValidationError


class AuthSecurityConfig(models.Model):
    _name = "auth.security.config"
    _description = "Authentication Security Configuration"
    _order = "id desc"

    name = fields.Char(required=True, default="Default Security Policy")
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        "res.company",
        required=True,
        default=lambda self: self.env.company,
        ondelete="cascade",
    )

    enable_login_attempt_tracking = fields.Boolean(default=True)
    enable_account_lock = fields.Boolean(default=True)
    max_failed_attempts = fields.Integer(default=5, required=True)
    lock_duration_minutes = fields.Integer(default=30, required=True)

    enable_session_tracking = fields.Boolean(default=True)
    session_timeout_minutes = fields.Integer(default=480, required=True)
    session_cleanup_days = fields.Integer(default=30, required=True)

    enable_ip_restriction = fields.Boolean(default=False)
    allowed_ip_addresses = fields.Text(
        help="Add one IPv4/IPv6 address or CIDR range per line. Leave empty to allow all IPs."
    )

    enable_email_otp = fields.Boolean(default=False)
    enable_totp = fields.Boolean(default=False)
    otp_expiration_minutes = fields.Integer(default=10, required=True)
    otp_max_attempts = fields.Integer(default=3, required=True)

    send_login_notification = fields.Boolean(default=True)
    track_user_activity = fields.Boolean(default=True)
    audit_password_reset = fields.Boolean(default=True)
    audit_retention_days = fields.Integer(default=365, required=True)

    _sql_constraints = [
        (
            "auth_security_config_company_name_unique",
            "unique(company_id, name)",
            "A security policy with this name already exists for this company.",
        ),
    ]

    @api.constrains(
        "max_failed_attempts",
        "lock_duration_minutes",
        "session_timeout_minutes",
        "session_cleanup_days",
        "otp_expiration_minutes",
        "otp_max_attempts",
        "audit_retention_days",
    )
    def _check_positive_values(self):
        for record in self:
            if record.max_failed_attempts <= 0:
                raise ValidationError(_("Maximum failed attempts must be greater than zero."))
            if record.lock_duration_minutes <= 0:
                raise ValidationError(_("Lock duration must be greater than zero."))
            if record.session_timeout_minutes <= 0:
                raise ValidationError(_("Session timeout must be greater than zero."))
            if record.session_cleanup_days <= 0:
                raise ValidationError(_("Session cleanup days must be greater than zero."))
            if record.otp_expiration_minutes <= 0:
                raise ValidationError(_("OTP expiration must be greater than zero."))
            if record.otp_max_attempts <= 0:
                raise ValidationError(_("OTP maximum attempts must be greater than zero."))
            if record.audit_retention_days <= 0:
                raise ValidationError(_("Audit retention days must be greater than zero."))

    @api.model
    def get_active_config(self):
        company = self.env.company
        config = self.sudo().search(
            [("active", "=", True), ("company_id", "=", company.id)],
            order="id desc",
            limit=1,
        )
        if not config:
            config = self.sudo().search([("active", "=", True)], order="id desc", limit=1)
        return config
