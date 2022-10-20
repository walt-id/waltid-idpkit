package id.walt.idp.oidc

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.client.*
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

            post(
                "par", documented(
                    document().operation {
                        it.summary("Pushed authorization request")
                            .addTagsItem("OIDC")
                            .operationId("par")
                    },
                    OIDCController::pushedAuthorizationRequest
                ), OIDCAuthorizationRole.OIDC_CLIENT
            )
            get(
                "authorize", documented(
                    document().operation {
                        it.summary("Authorization user agent endpoint")
                            .addTagsItem("OIDC")
                            .operationId("authorize")
                    },
                    OIDCController::authorizationRequest
                ), OIDCAuthorizationRole.UNAUTHORIZED
            )
            post(
                "token", documented(
                    document().operation {
                        it.summary("Token endpoint")
                            .addTagsItem("OIDC")
                            .operationId("token")
                    },
                    OIDCController::tokenRequest
                ), OIDCAuthorizationRole.OIDC_CLIENT
            )
            before("userInfo", JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))
            path("userInfo") {
                post(
                    documented(
                        document().operation {
                            it.summary("User Info POST endpoint")
                                .addTagsItem("OIDC")
                                .operationId("userInfo")
                        },
                        OIDCController::userInfoRequest
                    ), OIDCAuthorizationRole.ACCESS_TOKEN
                )
                get(
                    documented(
                        document().operation {
                            it.summary("User Info GET endpoint")
                                .addTagsItem("OIDC")
                                .operationId("userInfo")
                        },
                        OIDCController::userInfoRequest
                    ), OIDCAuthorizationRole.ACCESS_TOKEN
                )
            }
            before("clients/*", JavalinJWT.createHeaderDecodeHandler(OIDCManager.clientRegistrationTokenProvider))
            path("clients") {
                post(
                    "register", documented(
                        document().operation {
                            it.summary("Dynamic client registration endpoint")
                                .addTagsItem("OIDC")
                                .operationId("registerClient")
                        }.body<ClientMetadata>()
                            .json<ClientInformation>("200"),
                        OIDCController::registerClient
                    ), OIDCAuthorizationRole.INITIAL_CLIENT_REGISTRATION
                )
                put(
                    "{clientId}", documented(
                        document().operation {
                            it.summary("Dynamic client configuration endpoint")
                                .addTagsItem("OIDC")
                                .operationId("updateRegisteredClient")
                        }.body<ClientMetadata>()
                            .json<ClientInformation>("200"),
                        OIDCController::updateRegisteredClient
                    ), OIDCAuthorizationRole.CLIENT_REGISTRATION
                )
                get(
                    "{clientId}", documented(
                        document().operation {
                            it.summary("Read client registration info")
                                .addTagsItem("OIDC")
                                .operationId("getRegisteredClient")
                        }.json<ClientInformation>("200"),
                        OIDCController::getRegisteredClient
                    ), OIDCAuthorizationRole.CLIENT_REGISTRATION
                )
                delete(
                    "{clientId}", documented(
                        document().operation {
                            it.summary("Delete client registration info")
                                .addTagsItem("OIDC")
                                .operationId("deleteRegisteredClient")
                        }.json<ClientInformation>("200"),
                        OIDCController::deleteRegisteredClient
                    ), OIDCAuthorizationRole.CLIENT_REGISTRATION
                )
            }
        }

    private val log = KotlinLogging.logger {}

    private fun clientAccessControl(ctx: Context): Boolean {
        if (!ctx.basicAuthCredentialsExist()) {
            log.warn("Request required client authentication, but no basic auth credential was found")
            throw UnauthorizedResponse("Unauthorized")
        }
        val clientCreds = ctx.basicAuthCredentials()
        return OIDCManager.authorizeClient(clientCreds.username, clientCreds.password)
    }

    private fun getIDPClient(ctx: Context): ClientInformation {
        return OIDCClientRegistry.getClient(ctx.basicAuthCredentials().username)
            .orElseThrow { BadRequestResponse("Invalid client id") }
    }

    fun accessControl(ctx: Context, routeRoles: MutableSet<RouteRole>): Boolean {
        return routeRoles.contains(OIDCAuthorizationRole.UNAUTHORIZED) ||                                       // unauthorized endpoints
                routeRoles.contains(OIDCAuthorizationRole.OIDC_CLIENT) && clientAccessControl(ctx) ||            // endpoints requiring client authentication
                routeRoles.contains(OIDCAuthorizationRole.ACCESS_TOKEN) && JavalinJWT.containsJWT(ctx) ||        // endpoints requiring access_token
                routeRoles.contains(OIDCAuthorizationRole.CLIENT_REGISTRATION) && JavalinJWT.containsJWT(ctx) || // endpoints requiring client registration token
                routeRoles.contains(OIDCAuthorizationRole.INITIAL_CLIENT_REGISTRATION)                           // endpoints requiring initial client registration token
                && (IDPConfig.config.openClientRegistration || JavalinJWT.containsJWT(ctx))
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
        if (!OIDCManager.verifyClientRedirectUri(
                idpClient.id.value,
                authReq.redirectionURI.toString()
            )
        ) throw ForbiddenResponse("redirect_uri not allowed for client")
        val oidcSession = OIDCManager.initOIDCSession(authReq)
        ctx.status(HttpCode.CREATED).json(
            PushedAuthorizationSuccessResponse(
                URI.create("urn:ietf:params:oauth:request_uri:${oidcSession.id}"),
                OIDCManager.EXPIRATION_TIME.seconds
            ).toJSONObject()
        )
    }

    private fun authorizationRequest(ctx: Context) {
        val oidcSession = ctx.queryParam("request_uri")?.let {
            OIDCManager.getOIDCSession(it) ?: throw BadRequestResponse("Session not found or expired")
        } ?: OIDCManager.initOIDCSession(
            kotlin.runCatching {
                AuthorizationRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
            }.getOrElse {
                it.printStackTrace()
                throw BadRequestResponse("Error parsing OIDC authorization request from query parameters")
            }
        )

        ctx.status(HttpCode.FOUND).header("Location", OIDCManager.getWalletRedirectionUri(oidcSession).toString())
    }

    private fun tokenRequest(ctx: Context) {
        val tokenReq = kotlin.runCatching { TokenRequest.parse(ServletUtils.createHTTPRequest(ctx.req)) }
            .getOrElse { it.printStackTrace()
                throw BadRequestResponse(it.message ?: "Failed to parse token request") }
        if (tokenReq.authorizationGrant.type != GrantType.AUTHORIZATION_CODE) throw BadRequestResponse("Unsupported authorization grant type")
        val code = (tokenReq.authorizationGrant as AuthorizationCodeGrant).authorizationCode.value
        val redirectUri = (tokenReq.authorizationGrant as AuthorizationCodeGrant).redirectionURI.toString()
        val idpClient = getIDPClient(ctx)
        if (!OIDCManager.verifyClientRedirectUri(
                clientID = idpClient.id.value,
                redirectUri = redirectUri
            )
        ) {
            println("REDIRECT_URI NOT ALLOWED FOR ${idpClient.id.value}: $redirectUri")
            throw ForbiddenResponse("redirect_uri not allowed for client")
        }
        ctx.json(
            OIDCManager.getTokensFor(code, redirectUri).toJSONObject()
        )
    }

    private fun userInfoRequest(ctx: Context) {
        val session = kotlin.runCatching {
            OIDCManager.decodeAccessToken(JavalinJWT.getDecodedFromContext(ctx))
        }.getOrElse { exc ->
            exc.printStackTrace()
            throw BadRequestResponse(exc.message ?: "Bad request") }
        val verificationResult = session.verificationResult ?: throw BadRequestResponse("Session not yet verified")
        if (!verificationResult.isValid) throw BadRequestResponse("Session could not be verified")

        ctx.json(OIDCManager.getUserInfo(session).toJSONObject())
    }

    private fun verifyClientRegistrationAuth(ctx: Context, clientId: String?): Boolean {
        if (clientId.isNullOrEmpty() && IDPConfig.config.openClientRegistration) {
            // initial client registration is allowed unauthorized
            return true
        }

        val authClientId = JavalinJWT.getDecodedFromContext(ctx).subject
        if (clientId != null)
            return clientId == authClientId
        else
            return OIDCManager.NEW_CLIENT_REGISTRATION_ID == authClientId
    }

    private fun registerClient(ctx: Context) {
        if (!verifyClientRegistrationAuth(ctx, null)) {
            throw ForbiddenResponse("Forbidden")
        }
        val clientRegistrationRequest = ClientRegistrationRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
        try {
            val clientInfo = OIDCClientRegistry.registerClient(clientRegistrationRequest.clientMetadata, false)
            ctx.status(HttpCode.CREATED).json(
                clientInfo.toJSONObject()
            )
        } catch (exc: Exception) {
            exc.printStackTrace()
            ctx.status(HttpCode.BAD_REQUEST)
                .json(RegistrationError.INVALID_CLIENT_METADATA.setDescription(exc.message).toJSONObject())
        }
    }

    private fun getRegisteredClient(ctx: Context) {
        val clientId: String = ctx.pathParam("clientId")
        if (!verifyClientRegistrationAuth(ctx, clientId)) {
            throw ForbiddenResponse("Forbidden")
        }
        val clientInfo =
            OIDCClientRegistry.getClient(clientId).orElseThrow { UnauthorizedResponse("Client with the given ID not found.") }
        ctx.json(clientInfo.toJSONObject())
    }

    private fun updateRegisteredClient(ctx: Context) {
        val clientId: String = ctx.pathParam("clientId")
        if (!verifyClientRegistrationAuth(ctx, clientId)) {
            throw ForbiddenResponse("Forbidden")
        }
        val clientUpdateRequest = ClientUpdateRequest.parse(ServletUtils.createHTTPRequest(ctx.req))
        if (clientUpdateRequest.clientID.value != clientId) throw BadRequestResponse("Wrong client ID in request body")
        val clientInfo =
            OIDCClientRegistry.getClient(clientId).orElseThrow { UnauthorizedResponse("Client with given ID not found.") }
        if (clientUpdateRequest.clientSecret != null && clientUpdateRequest.clientSecret.value != clientInfo.secret.value) throw BadRequestResponse(
            "Wrong client secret in request body"
        )
        try {
            val updatedInfo = OIDCClientRegistry.updateClient(clientInfo, clientUpdateRequest.clientMetadata, false)
            ctx.json(
                updatedInfo.toJSONObject()
            )
        } catch (exc: Exception) {
            exc.printStackTrace()
            ctx.status(HttpCode.BAD_REQUEST)
                .json(RegistrationError.INVALID_CLIENT_METADATA.setDescription(exc.message).toJSONObject())
        }
    }

    private fun deleteRegisteredClient(ctx: Context) {
        val clientId: String = ctx.pathParam("clientId")
        if (!verifyClientRegistrationAuth(ctx, clientId)) {
            throw ForbiddenResponse("Forbidden")
        }
        val clientInfo =
            OIDCClientRegistry.getClient(clientId).orElseThrow { UnauthorizedResponse("Client with given ID not found.") }
        OIDCClientRegistry.unregisterClient(clientInfo)
        ctx.status(HttpCode.NO_CONTENT)
    }
}
