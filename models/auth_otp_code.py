from datetime import timedelta

from odoo import api, fields, models


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
    def _cron_cleanup_expired_codes(self):
        cutoff = fields.Datetime.now() - timedelta(days=1)
        self.sudo().search(
            [
                "|",
                ("expires_at", "<", cutoff),
                ("used_at", "<", cutoff),
            ]
        ).unlink()
