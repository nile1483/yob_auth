"""Illustrative thin yob_auth endpoint using the core boundary."""

from __future__ import annotations

import frappe

from yob_auth.services.authentication import authenticate_password
from yob_core.api.boundary import yob_api
from yob_core.api.response import success_response


@frappe.whitelist(allow_guest=True, methods=["POST"])
@yob_api
def login_with_password(application: str, username: str, password: str):
	"""Authenticate, resolve access, and create a normal Frappe session."""
	result = authenticate_password(
		application=application,
		username=username,
		password=password,
	)
	return success_response(
		{
			"authenticated": True,
			"authentication_method": "password",
			"user": result.user,
			"context": result.context.as_dict(),
			"csrf_token": result.csrf_token,
		},
		notice="Login successful.",
	)
