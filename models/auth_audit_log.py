from datetime import timedelta

from odoo import api, fields, models


class AuthAuditLog(models.Model):
    _name = "auth.audit.log"
    _description = "Authentication Audit Log"
    _order = "event_at desc, id desc"
    _rec_name = "event_type"

    event_type = fields.Selection(
        [
            ("login_success", "Login Success"),
            ("login_failure", "Login Failure"),
            ("logout", "Logout"),
            ("account_locked", "Account Locked"),
            ("password_reset_requested", "Password Reset Requested"),
            ("password_reset_completed", "Password Reset Completed"),
            ("otp_sent", "OTP Sent"),
            ("otp_verified", "OTP Verified"),
            ("otp_failed", "OTP Failed"),
            ("session_terminated", "Session Terminated"),
            ("ip_restricted", "IP Restricted"),
            ("settings_changed", "Settings Changed"),
            ("access_denied", "Access Denied"),
        ],
        required=True,
        index=True,
    )
    severity = fields.Selection(
        [
            ("info", "Info"),
            ("warning", "Warning"),
            ("critical", "Critical"),
        ],
        default="info",
        required=True,
        index=True,
    )
    user_id = fields.Many2one("res.users", string="Affected User", index=True, ondelete="set null")
    actor_id = fields.Many2one(
        "res.users",
        string="Actor",
        default=lambda self: self.env.user,
        index=True,
        ondelete="set null",
    )
    company_id = fields.Many2one(
        "res.company",
        default=lambda self: self.env.company,
        index=True,
        ondelete="set null",
    )
    ip_address = fields.Char(index=True)
    user_agent = fields.Text()
    model_name = fields.Char()
    record_id = fields.Integer()
    description = fields.Text()
    metadata = fields.Text()
    event_at = fields.Datetime(default=fields.Datetime.now, required=True, index=True)

    @api.model
    def log_event(self, event_type, user=None, severity="info", description=None, **extra_values):
        values = {
            "event_type": event_type,
            "severity": severity,
            "description": description,
        }
        if user:
            values["user_id"] = user.id
        values.update(extra_values)
        return self.sudo().create(values)

    @api.model
    def _cron_cleanup_old_logs(self):
        config = self.env["auth.security.config"].sudo().get_active_config()
        if not config:
            return

        cutoff = fields.Datetime.now() - timedelta(days=config.audit_retention_days)
        self.sudo().search([("event_at", "<", cutoff)]).unlink()
