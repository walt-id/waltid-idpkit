package id.walt.idp.oidc

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.interfaces.DecodedJWT
import com.google.common.cache.CacheBuilder
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.*
import com.nimbusds.openid.connect.sdk.OIDCScopeValue
import com.nimbusds.openid.connect.sdk.SubjectType
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.idp.IDPManager
import id.walt.idp.IDPType
import id.walt.idp.config.IDPConfig
import id.walt.idp.siop.SIOPState
import id.walt.services.jwt.JwtService
import id.walt.services.oidc.OIDCUtils
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.VerifierManager
import io.javalin.http.BadRequestResponse
import io.javalin.http.ForbiddenResponse
import io.javalin.http.InternalServerErrorResponse
import javalinjwt.JWTProvider
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeUnit

object OIDCManager : IDPManager {
  val EXPIRATION_TIME: Duration = Duration.ofMinutes(5)
  val sessionCache = CacheBuilder.newBuilder().expireAfterAccess(EXPIRATION_TIME.seconds, TimeUnit.SECONDS).build<String, OIDCSession>()

  val oidcProviderMetadata get() = OIDCProviderMetadata(
    Issuer(oidcApiUrl),
    listOf(SubjectType.PUBLIC),
    // TODO: provide this endpoint !!
    URI.create("$oidcApiUrl/jwkSet")
  ).apply {
    authorizationEndpointURI = URI.create("$oidcApiUrl/authorize")
    pushedAuthorizationRequestEndpointURI = URI.create("$oidcApiUrl/par")
    tokenEndpointURI = URI.create("$oidcApiUrl/token")
    userInfoEndpointURI = URI.create("$oidcApiUrl/userInfo")
    grantTypes = listOf(GrantType.AUTHORIZATION_CODE)
    responseTypes = listOf(ResponseType.CODE)
    claims = listOf("vp_token")
    setCustomParameter("wallets_supported", VerifierConfig.config.wallets.values.map { wallet ->
      mapOf(
        "id" to wallet.id,
        "description" to wallet.description
      )
    })
  }

  fun initOIDCSession(authRequest: AuthorizationRequest): OIDCSession {
    val vpTokenClaim = OIDCUtils.getVCClaims(authRequest).vp_token ?: throw BadRequestResponse("Missing VP token claim in authorization request")
    val walletId = authRequest.customParameters["walletId"]?.firstOrNull() ?: VerifierConfig.config.wallets.values.map { wc -> wc.id }.firstOrNull() ?: throw InternalServerErrorResponse("Known wallets not configured")
    val wallet = VerifierConfig.config.wallets[walletId] ?: throw BadRequestResponse("No wallet configuration found for given walletId")
    if(authRequest.responseType != ResponseType.CODE) throw BadRequestResponse("Only code flow is currently supported")
    return OIDCSession(
      id = UUID.randomUUID().toString(),
      authRequest = authRequest,
      vpTokenClaim = vpTokenClaim,
      wallet = wallet
    )
  }

  fun getOIDCSession(id: String): OIDCSession? {
    return sessionCache.getIfPresent(id.replaceFirst("urn:ietf:params:oauth:request_uri:",""))
  }

  fun updateOIDCSession(session: OIDCSession) {
    sessionCache.put(session.id, session)
  }

  val oidcApiPath: String = "api/oidc"
  val oidcApiUrl: String get() = "${IDPConfig.config.externalUrl}/$oidcApiPath"

  fun getWalletRedirectionUri(session: OIDCSession): URI {
    val siopReq = VerifierManager.getService().newRequest(
      tokenClaim = session.vpTokenClaim,
      state = SIOPState(IDP_TYPE, session.id).encode()
    )
    return URI.create("${session.wallet.url}/${session.wallet.presentPath}?${siopReq.toUriQueryString()}")
  }

  fun getAccessTokenFor(code: String, redirect_uri: String): AccessTokenResponse {
    val session = getOIDCSession(code) ?: throw BadRequestResponse("Invalid authorization code")
    if(!session.authRequest.redirectionURI.equals(URI.create(redirect_uri)))
      throw ForbiddenResponse("Redirection URI doesn't match OIDC session for given code")
    return AccessTokenResponse(
      Tokens(
        BearerAccessToken(
          accessTokenProvider.generateToken(session),
          EXPIRATION_TIME.seconds,
          Scope(OIDCScopeValue.OPENID)
        ),
        RefreshToken()
      )
    )
  }

  val jwtAlgorithm = Algorithm.HMAC256("FOO") // TODO: set algorithm and key according to key config

  val accessTokenProvider = JWTProvider(
    jwtAlgorithm,
    { session: OIDCSession, alg: Algorithm? ->
      JWT.create().withSubject(session.id).withAudience(session.authRequest.redirectionURI.toString()).sign(alg)
    },
    JWT.require(jwtAlgorithm).build()
  )

  fun decodeAccessToken(decodedJWT: DecodedJWT): OIDCSession {
    val session = sessionCache.getIfPresent(decodedJWT.subject) ?: throw JWTDecodeException("Invalid oidc session id")
    if(!decodedJWT.audience.contains(session.authRequest.redirectionURI.toString())) throw JWTDecodeException("Invalid audience for session")
    return session
  }

  private fun errorDescriptionFor(verificationResult: SIOPResponseVerificationResult): String {
    verificationResult.subject ?: return "Subject not defined"
    verificationResult.request ?: return "No SIOP request defined"
    if(!verificationResult.id_token_valid) return "Invalid id_token"
    val vpVerificationResult = verificationResult.verification_result ?: return "Verifiable presentation not verified"
    if(!vpVerificationResult.valid) return "Verifiable presentation invalid: ${vpVerificationResult}"
    return "Invalid SIOP response verification result"
  }

  override fun continueIDPSessionForSIOPResponse(sessionId: String, verificationResult: SIOPResponseVerificationResult): URI {
    val session = getOIDCSession(sessionId) ?: throw BadRequestResponse("OIDC session invalid or expired")
    if(verificationResult.isValid) {
      session.verificationResult = verificationResult
      updateOIDCSession(session)
      return URI.create("${session.authRequest.redirectionURI}" +
          "?code=${sessionId}" +
          "&state=${session.authRequest.state}")
    } else {
      return URI.create("${session.authRequest.redirectionURI}" +
          "?error=invalid_request" +
          "&error_description=${URLEncoder.encode(errorDescriptionFor(verificationResult), StandardCharsets.UTF_8)}" +
          "&state=${session.authRequest.state}")
    }
  }

  override val IDP_TYPE = IDPType.OIDC
}
