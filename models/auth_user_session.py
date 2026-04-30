from datetime import timedelta

from odoo import api, fields, models


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
    session_token = fields.Char(index=True, copy=False)
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
