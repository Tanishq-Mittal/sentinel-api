"""Authentication endpoints for the local sandbox."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from ..auth import (
    SessionPrincipal,
    authentication_error,
    get_auth_service,
    get_current_principal,
)
from ..schemas import TokenResponse, UserIdentity


router = APIRouter(prefix="/v1/auth", tags=["authentication"])


@router.post(
    "/token",
    response_model=TokenResponse,
    operation_id="login_for_access_token",
    summary="Authenticate a synthetic test user",
    description=(
        "Issues an ephemeral bearer token for one of the two local fixture users. "
        "The endpoint uses synthetic credentials and does not contact an identity provider."
    ),
    responses={
        401: {"description": "Invalid credentials"},
        413: {"description": "Request body too large"},
    },
)
def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> TokenResponse:
    if form_data.grant_type not in (None, "password"):
        raise authentication_error()

    auth_service = get_auth_service(request)
    user = auth_service.authenticate(form_data.username, form_data.password)
    if user is None:
        raise authentication_error()

    token = auth_service.issue_token(user)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return TokenResponse(
        access_token=token,
        expires_in=request.app.state.settings.session_ttl_seconds,
    )


@router.get(
    "/me",
    response_model=UserIdentity,
    operation_id="get_authenticated_identity",
    summary="Get the active synthetic identity",
    responses={401: {"description": "Invalid or expired authentication"}},
)
def get_authenticated_identity(
    principal: SessionPrincipal = Depends(get_current_principal),
) -> UserIdentity:
    return UserIdentity(
        user_id=principal.user.user_id,
        username=principal.user.username,
        display_name=principal.user.display_name,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="logout_current_session",
    summary="Invalidate the current bearer session",
    responses={
        401: {"description": "Invalid or expired authentication"},
        413: {"description": "Request body too large"},
    },
)
def logout_current_session(
    request: Request,
    principal: SessionPrincipal = Depends(get_current_principal),
) -> Response:
    get_auth_service(request).revoke(principal.token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
