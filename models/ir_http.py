import logging

from odoo import models
from odoo.http import request


_logger = logging.getLogger(__name__)


class IrHttp(models.AbstractModel):
    _inherit = "ir.http"

    def session_info(self):
        session_info = super().session_info()
        try:
            if request and request.session.uid:
                self.env["auth.user.session"].sudo()._sync_current_session()
        except Exception:
            _logger.exception("Could not sync enterprise security session")
        return session_info

    @classmethod
    def _post_logout(cls):
        try:
            if request and request.env:
                request.env["auth.user.session"].sudo()._close_current_session()
        except Exception:
            _logger.exception("Could not close enterprise security session on logout")
        return super()._post_logout()
