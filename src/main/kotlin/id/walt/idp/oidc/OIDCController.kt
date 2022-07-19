package id.walt.idp.oidc

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.http.ServletUtils
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.idp.config.IDPConfig
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.core.security.RouteRole
import io.javalin.http.*
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT
import mu.KotlinLogging
import java.net.URI

object OIDCController {
  val routes
    get() = path("") {

      get(".well-known/openid-configuration", documented(
        document().operation {
          it.summary("get OIDC provider meta data")
            .addTagsItem("OIDC")
            .operationId("oidcProviderMeta")
        }
        .json<OIDCProviderMetadata>("200"),
        OIDCController::openIdConfiguration
      ), OIDCAuthorizationRole.UNAUTHORIZED)
      get("jwkSet", documented(
      document().operation {
        it.summary("get OIDC JWK set")
          .addTagsItem("OIDC")
          .operationId("jwkSet")
      }
        .json<JWKSet>("200"),
      OIDCController::jwkSet
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
         it.summary("Token endpoint")
           .addTagsItem("OIDC")
           .operationId("token")
        },
        OIDCController::tokenRequest
      ), OIDCAuthorizationRole.OIDC_CLIENT)
      before("userInfo", JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))
      path("userInfo") {
        post(documented(
            document().operation {
              it.summary("User Info POST endpoint")
                .addTagsItem("OIDC")
                .operationId("userInfo")
            },
            OIDCController::userInfoRequest
          ), OIDCAuthorizationRole.ACCESS_TOKEN
        )
        get(documented(
            document().operation {
              it.summary("User Info GET endpoint")
                .addTagsItem("OIDC")
                .operationId("userInfo")
            },
            OIDCController::userInfoRequest
          ), OIDCAuthorizationRole.ACCESS_TOKEN
        )
      }
    }

  private val log = KotlinLogging.logger {}

  private fun clientAccessControl(ctx: Context): Boolean {
    if(!ctx.basicAuthCredentialsExist()) {
      log.warn("Request required client authentication, but no basic auth credential was found")
      throw UnauthorizedResponse("Unauthorized")
    }
    val clientCreds = ctx.basicAuthCredentials()
    return OIDCManager.authorizeClient(clientCreds.username, clientCreds.password)
  }

  private fun getIDPClient(ctx: Context): ClientInformation {
    return OIDCClientRegistry.getClient(ctx.basicAuthCredentials().username).orElseThrow { BadRequestResponse("Invalid client id") }
  }

  fun accessControl(ctx: Context, routeRoles: MutableSet<RouteRole>): Boolean {
    return  routeRoles.contains(OIDCAuthorizationRole.UNAUTHORIZED) ||                              // unauthorized endpoints
            routeRoles.contains(OIDCAuthorizationRole.OIDC_CLIENT) && clientAccessControl(ctx) ||   // endpoints requiring client authentication
            routeRoles.contains(OIDCAuthorizationRole.ACCESS_TOKEN) && JavalinJWT.containsJWT(ctx)  // endpoints requiring access_token
  }

  private fun openIdConfiguration(ctx: Context) {
    ctx.json(OIDCManager.oidcProviderMetadata.toJSONObject())
  }

  private fun jwkSet(ctx: Context) {
    ctx.json(OIDCManager.keySet.toJSONObject(true))
  }

  private fun pushedAuthorizationRequest(ctx: Context) {
    val authReq = AuthorizationRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
    val idpClient = getIDPClient(ctx)
    if(!OIDCManager.verifyClientRedirectUri(idpClient.id.value, authReq.redirectionURI.toString())) throw ForbiddenResponse("redirect_uri not allowed for client")
    val oidcSession = OIDCManager.initOIDCSession(authReq)
    ctx.status(HttpCode.CREATED).json(PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:${oidcSession.id}"), OIDCManager.EXPIRATION_TIME.seconds).toJSONObject())
  }

  private fun authorizationRequest(ctx: Context) {
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

  private fun tokenRequest(ctx: Context) {
    val tokenReq = kotlin.runCatching { TokenRequest.parse(ServletUtils.createHTTPRequest(ctx.req)) }.getOrElse { throw BadRequestResponse(it.message ?: "Failed to parse token request") }
    if(tokenReq.authorizationGrant.type != GrantType.AUTHORIZATION_CODE) throw BadRequestResponse("Unsupported authorization grant type")
    val code = (tokenReq.authorizationGrant as AuthorizationCodeGrant).authorizationCode.value
    val redirectUri = (tokenReq.authorizationGrant as AuthorizationCodeGrant).redirectionURI.toString()
    val idpClient = getIDPClient(ctx)
    if(!OIDCManager.verifyClientRedirectUri(idpClient.id.value, redirectUri)) throw ForbiddenResponse("redirect_uri not allowed for client")
    ctx.json(
      OIDCManager.getTokensFor(code, redirectUri).toJSONObject()
    )
  }

  private fun userInfoRequest(ctx: Context) {
    val session = kotlin.runCatching {
      OIDCManager.decodeAccessToken(JavalinJWT.getDecodedFromContext(ctx))
    }.getOrElse { exc -> throw BadRequestResponse(exc.message ?: "Bad request") }
    val verificationResult = session.verificationResult ?: throw BadRequestResponse("Session not yet verified")
    if(!verificationResult.isValid) throw BadRequestResponse("Session could not be verified")
    verificationResult.vp_token ?: throw BadRequestResponse("No vp_token found for session")

    ctx.json(OIDCManager.getUserInfo(session).toJSONObject())
  }
}
