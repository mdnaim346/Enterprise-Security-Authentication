import logging

from odoo import http, _
from odoo.exceptions import AccessDenied, UserError
from odoo.http import request

from odoo.addons.web.controllers import home as web_home


_logger = logging.getLogger(__name__)


class Home(web_home.Home):
    def _esa_get_session_otp(self, user, config):
        otp_id = request.session.get("esa_otp_id")
        if not otp_id:
            return request.env["auth.otp.code"].browse()

        otp = request.env["auth.otp.code"].sudo().browse(otp_id).exists()
        if (
            otp
            and otp.user_id.id == user.id
            and otp.purpose == "login"
            and otp.delivery_channel == "email"
            and otp._esa_is_usable(config)
        ):
            return otp
        return request.env["auth.otp.code"].browse()

    def _esa_send_login_otp(self, user, config, request_values):
        otp = request.env["auth.otp.code"].sudo()._esa_create_email_login_otp(
            user,
            config,
            request_values,
        )
        request.session["esa_otp_id"] = otp.id
        request.session.touch()
        return otp

    def _esa_ensure_login_otp(self, user, config, request_values, force_new=False):
        if not force_new:
            otp = self._esa_get_session_otp(user, config)
            if otp:
                return otp
        return self._esa_send_login_otp(user, config, request_values)

    def _esa_finalize_otp_login(self, user, login, request_values, config, redirect=None):
        request.session.pop("esa_otp_id", None)
        request.session.finalize(request.env)
        request.update_env(user=request.session.uid)
        request.update_context(**request.session.context)

        verified_user = request.env["res.users"].sudo().browse(user.id)
        request.env["auth.audit.log"].log_event(
            "otp_verified",
            user=verified_user,
            severity="info",
            description=_("Email OTP verified for login"),
            ip_address=request_values.get("ip_address"),
            user_agent=request_values.get("user_agent"),
        )
        request.env["res.users"].sudo()._esa_record_mfa_login_success(
            verified_user,
            login,
            request_values,
            config,
        )

        request.session.touch()
        return request.redirect(self._login_redirect(request.session.uid, redirect=redirect))

    @http.route(
        "/web/login/esa_otp",
        type="http",
        auth="public",
        methods=["GET", "POST"],
        sitemap=False,
        website=True,
        multilang=False,
    )
    def web_esa_otp(self, redirect=None, **kwargs):
        if request.session.uid:
            return request.redirect(self._login_redirect(request.session.uid, redirect=redirect))

        if not request.session.pre_uid:
            return request.redirect("/web/login")

        user = request.env["res.users"].sudo().browse(request.session.pre_uid).exists()
        if not user:
            return request.redirect("/web/login")

        config = request.env["auth.security.config"].sudo().get_active_config()
        login = request.session.pre_login or user.login
        request_values = request.env["res.users"].sudo()._esa_request_values({})
        error = None
        message = None

        if not config or not config.enable_email_otp:
            return self._esa_finalize_otp_login(user, login, request_values, config, redirect=redirect)

        try:
            if request.httprequest.method == "POST" and kwargs.get("otp_code"):
                otp = self._esa_get_session_otp(user, config)
                if not otp:
                    self._esa_send_login_otp(user, config, request_values)
                    raise AccessDenied(_("The verification code expired. A new code has been sent."))

                try:
                    with user._assert_can_auth(user=user.id):
                        otp._esa_check_login_code(kwargs.get("otp_code"), config)
                except AccessDenied as access_error:
                    request.env["auth.audit.log"].log_event(
                        "otp_failed",
                        user=user,
                        severity="warning",
                        description=str(access_error),
                        ip_address=request_values.get("ip_address"),
                        user_agent=request_values.get("user_agent"),
                    )
                    raise

                return self._esa_finalize_otp_login(user, login, request_values, config, redirect=redirect)

            if request.httprequest.method == "POST" and kwargs.get("send_email"):
                self._esa_ensure_login_otp(user, config, request_values, force_new=True)
                message = _("A new verification code was sent.")
            else:
                self._esa_ensure_login_otp(user, config, request_values)
        except AccessDenied as access_error:
            error = str(access_error)
        except UserError as user_error:
            error = user_error.args[0] if user_error.args else str(user_error)
        except Exception:
            _logger.exception("Could not process email OTP login for user %s", user.login)
            error = _("Could not process the verification code. Please try again.")

        request.session.touch()
        return request.render(
            "enterprise_security_authentication.esa_otp_login_form",
            {
                "user": user,
                "error": error,
                "message": message,
                "redirect": redirect,
                "expiration_minutes": config.otp_expiration_minutes if config else 0,
            },
        )
