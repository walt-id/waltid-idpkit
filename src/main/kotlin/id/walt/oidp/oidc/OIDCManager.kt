package id.walt.oidp.oidc

import com.google.common.cache.CacheBuilder
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.openid.connect.sdk.OIDCScopeValue
import com.nimbusds.openid.connect.sdk.SubjectType
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.WALTID_DATA_ROOT
import id.walt.issuer.backend.IssuanceSession
import id.walt.issuer.backend.IssuerManager
import id.walt.model.oidc.SIOPv2Request
import id.walt.model.oidc.VpTokenClaim
import id.walt.oidp.config.OIDPConfig
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.hkvstore.FileSystemHKVStore
import id.walt.services.hkvstore.FilesystemStoreConfig
import id.walt.services.keystore.HKVKeyStoreService
import id.walt.services.oidc.OIDCUtils
import id.walt.services.vcstore.HKVVcStoreService
import id.walt.verifier.backend.ResponseVerification
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.VerifierManager
import id.walt.webwallet.backend.context.UserContext
import io.javalin.http.BadRequestResponse
import io.javalin.http.InternalServerErrorResponse
import java.net.URI
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeUnit

class OIDCManager: VerifierManager() {
  val EXPIRATION_TIME: Duration = Duration.ofMinutes(5)
  val sessionCache = CacheBuilder.newBuilder().expireAfterAccess(IssuerManager.EXPIRATION_TIME.seconds, TimeUnit.SECONDS).build<String, OIDCSession>()

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

  override val verifierApiPath: String = "api/siop"
  override val verifierUiPath: String = ""
  val oidcApiPath: String = "api/oidc"
  val oidcApiUrl: String get() = "${OIDPConfig.config.externalUrl}/$oidcApiPath"

  fun getWalletRedirectionUri(session: OIDCSession): URI {
    val siopReq = newRequest(session.vpTokenClaim)
    return URI.create("${session.wallet.url}/${session.wallet.presentPath}?${siopReq.toUriQueryString()}")
  }

  override fun verifyResponse(reqId: String, id_token: String, vp_token: String): ResponseVerification? {
    // TODO: override ?
    return super.verifyResponse(reqId, id_token, vp_token)
  }


  override val verifierContext = UserContext(
    contextId = "OIDCManager",
    hkvStore = FileSystemHKVStore(FilesystemStoreConfig("${WALTID_DATA_ROOT}/data/oidc")),
    keyStore = HKVKeyStoreService(),
    vcStore = HKVVcStoreService()
  )

  companion object {
    fun getService() = ServiceRegistry.getService<VerifierManager>() as OIDCManager
  }
}
