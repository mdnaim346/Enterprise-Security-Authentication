from odoo import fields, models


class AuthLoginAttempt(models.Model):
    _name = "auth.login.attempt"
    _description = "Login Attempt"
    _order = "attempted_at desc, id desc"
    _rec_name = "login"

    login = fields.Char(required=True, index=True)
    user_id = fields.Many2one("res.users", string="User", index=True, ondelete="set null")
    company_id = fields.Many2one(
        "res.company",
        default=lambda self: self.env.company,
        index=True,
        ondelete="set null",
    )
    ip_address = fields.Char(index=True)
    user_agent = fields.Text()
    attempted_at = fields.Datetime(default=fields.Datetime.now, required=True, index=True)
    success = fields.Boolean(default=False, index=True)
    failure_reason = fields.Char()
    locked_until = fields.Datetime()
