package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationCode
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.PushedAuthorizationSuccessResponse
import com.nimbusds.oauth2.sdk.http.ServletUtils
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.webwallet.backend.auth.UserRole
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.core.security.RouteRole
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.HttpCode
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT
import java.net.URI

object OIDCController {
  val routes
    get() = path("") {
      before(JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))
      get(".well-known/openid-configuration", documented(
        document().operation {
          it.summary("get OIDC provider meta data")
            .addTagsItem("OIDC")
            .operationId("oidcProviderMeta")
        }
        .json<OIDCProviderMetadata>("200"),
        OIDCController::openIdConfiguration
      ), OIDCAuthorizationRole.UNAUTHORIZED)
      post("par", documented(
        document().operation {
          it.summary("Pushed authorization request")
            .addTagsItem("OIDC")
            .operationId("par")
        },
        OIDCController::pushedAuthorizationRequest
      ), OIDCAuthorizationRole.OIDC_CLIENT)
      get("authorize", documented(
        document().operation {
         it.summary("Authorization user agent endpoint")
           .addTagsItem("OIDC")
           .operationId("authorize")
        },
        OIDCController::authorizationRequest
      ), OIDCAuthorizationRole.UNAUTHORIZED)
      post("token", documented(
        document().operation {
         it.summary("Token endoint")
           .addTagsItem("OIDC")
           .operationId("token")
        },
        OIDCController::tokenRequest
      ), OIDCAuthorizationRole.OIDC_CLIENT)
      post("userInfo", documented(
        document().operation {
         it.summary("User Info endpoint")
           .addTagsItem("OIDC")
           .operationId("userInfo")
        },
        OIDCController::userInfoRequest
      ), OIDCAuthorizationRole.ACCESS_TOKEN)
    }

  fun accessControl(ctx: Context, routeRoles: MutableSet<RouteRole>): Boolean {
    return routeRoles.contains(OIDCAuthorizationRole.UNAUTHORIZED) ||
        // TODO: implement OIDC client authorization
        routeRoles.contains(OIDCAuthorizationRole.OIDC_CLIENT) ||
        routeRoles.contains(OIDCAuthorizationRole.ACCESS_TOKEN) && JavalinJWT.containsJWT(ctx)
  }

  fun openIdConfiguration(ctx: Context) {
    ctx.json(OIDCManager.oidcProviderMetadata.toJSONObject())
  }

  fun pushedAuthorizationRequest(ctx: Context) {
    val authReq = AuthorizationRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
    val oidcSession = OIDCManager.initOIDCSession(authReq)
    ctx.status(HttpCode.CREATED).json(PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:${oidcSession.id}"), OIDCManager.EXPIRATION_TIME.seconds).toJSONObject())
  }

  fun authorizationRequest(ctx: Context) {
    val oidcSession = ctx.queryParam("request_uri")?.let {
      OIDCManager.getOIDCSession(it) ?: throw BadRequestResponse("Session not found or expired")
    } ?: OIDCManager.initOIDCSession(
      kotlin.runCatching {
        AuthorizationRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
      }.getOrElse {
        throw BadRequestResponse("Error parsing OIDC authorization request from query parameters")
      }
    )

    ctx.status(HttpCode.FOUND).header("Location", OIDCManager.getWalletRedirectionUri(oidcSession).toString())
  }

  fun tokenRequest(ctx: Context) {
    val code = ctx.formParam("code") ?: throw BadRequestResponse("No authorization code specified")
    val redirect_uri = ctx.formParam("redirect_uri") ?: throw BadRequestResponse("No redirect_uri specified")
    ctx.json(
      OIDCManager.getAccessTokenFor(code, redirect_uri).toJSONObject()
    )
  }

  fun userInfoRequest(ctx: Context) {
    val session = kotlin.runCatching {
      OIDCManager.decodeAccessToken(JavalinJWT.getDecodedFromContext(ctx))
    }.getOrElse { exc -> throw BadRequestResponse(exc.message ?: "Bad request") }
    val verificationResult = session.verificationResult ?: throw BadRequestResponse("Session not yet verified")
    if(!verificationResult.isValid) throw BadRequestResponse("Session could not be verified")
    val vp_token = verificationResult.vp_token ?: throw BadRequestResponse("No vp_token found for session")

    ctx.json(vp_token.toMap())
  }
}
