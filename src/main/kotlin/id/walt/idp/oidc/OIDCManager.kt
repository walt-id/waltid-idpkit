package id.walt.idp.oidc

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.interfaces.DecodedJWT
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.LoadingCache
import com.jayway.jsonpath.JsonPath
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.openid.connect.sdk.*
import com.nimbusds.openid.connect.sdk.claims.UserInfo
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.token.OIDCTokens
import id.walt.WALTID_DATA_ROOT
import id.walt.common.client
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.idp.IDPManager
import id.walt.idp.IDPType
import id.walt.idp.config.IDPConfig
import id.walt.idp.nfts.NFTManager
import id.walt.idp.siop.SIOPState
import id.walt.idp.util.WaltIdAlgorithm
import id.walt.model.dif.*
import id.walt.model.oidc.VpTokenClaim
import id.walt.services.hkvstore.FileSystemHKVStore
import id.walt.services.hkvstore.FilesystemStoreConfig
import id.walt.services.key.KeyFormat
import id.walt.services.key.KeyService
import id.walt.services.keystore.HKVKeyStoreService
import id.walt.services.keystore.KeyType
import id.walt.services.oidc.OIDCUtils
import id.walt.services.vcstore.HKVVcStoreService
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.VerifierManager
import id.walt.webwallet.backend.context.UserContext
import id.walt.webwallet.backend.context.WalletContextManager
import io.javalin.http.BadRequestResponse
import io.javalin.http.ForbiddenResponse
import io.javalin.http.InternalServerErrorResponse
import javalinjwt.JWTProvider
import mu.KotlinLogging
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeUnit

object OIDCManager : IDPManager {
  val EXPIRATION_TIME: Duration = Duration.ofMinutes(5)
  private val sessionCache: Cache<String, OIDCSession> = CacheBuilder.newBuilder().expireAfterAccess(EXPIRATION_TIME.seconds, TimeUnit.SECONDS).build()
  private val log = KotlinLogging.logger {}

  val oidcContext = UserContext(
    contextId = "OIDCContext",
    hkvStore = FileSystemHKVStore(FilesystemStoreConfig("$WALTID_DATA_ROOT/data/idp")),
    keyStore = HKVKeyStoreService(),
    vcStore = HKVVcStoreService()
  )

  private lateinit var keyId: KeyId
  private lateinit var jwtAlgorithm: Algorithm
  lateinit var keySet: JWKSet

  init {
    WalletContextManager.runWith(oidcContext) {
      keyId = if(IDPConfig.config.keyId.isNotEmpty()) {
        KeyId(IDPConfig.config.keyId)
      } else {
        KeyService.getService().listKeys().map { k -> k.keyId }.firstOrNull()
          ?: KeyService.getService().generate(KeyAlgorithm.RSA)
      }
      val key = KeyService.getService().load(keyId.id)
      keySet = JWKSet(JWK.parse(KeyService.getService().export(keyId.id, KeyFormat.JWK, KeyType.PUBLIC)))
      jwtAlgorithm = WaltIdAlgorithm(keyId, oidcContext, key.algorithm)
      log.info("Using IDP key: {}", keyId)
    }
  }

  val oidcProviderMetadata get() = OIDCProviderMetadata(
    Issuer(oidcApiUrl),
    listOf(SubjectType.PUBLIC),
    URI.create("$oidcApiUrl/jwkSet")
  ).apply {
    authorizationEndpointURI = URI.create("$oidcApiUrl/authorize")
    pushedAuthorizationRequestEndpointURI = URI.create("$oidcApiUrl/par")
    tokenEndpointURI = URI.create("$oidcApiUrl/token")
    userInfoEndpointURI = URI.create("$oidcApiUrl/userInfo")
    grantTypes = listOf(GrantType.AUTHORIZATION_CODE)
    responseTypes = listOf(ResponseType.CODE, ResponseType.IDTOKEN, ResponseType.TOKEN, ResponseType.CODE_IDTOKEN, ResponseType.CODE_TOKEN, ResponseType.IDTOKEN_TOKEN, ResponseType.CODE_IDTOKEN_TOKEN)
    claims = listOf("vp_token", *(IDPConfig.config.claimMappings?.mappings?.map { m -> m.claim }?.toSet() ?: setOf()).toTypedArray())
    scopes = Scope("openid", *(IDPConfig.config.claimMappings?.mappings?.flatMap { m -> m.scope }?.toSet() ?: setOf()).toTypedArray())
    setCustomParameter("wallets_supported", VerifierConfig.config.wallets.values.map { wallet ->
      mapOf(
        "id" to wallet.id,
        "description" to wallet.description
      )
    })
    tokenEndpointAuthMethods = listOf(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
  }

  private fun generateVpTokenClaim(authRequest: AuthorizationRequest): VpTokenClaim {
    return OIDCUtils.getVCClaims(authRequest).vp_token ?:
      VpTokenClaim(PresentationDefinition(
        id = "1",
        input_descriptors = authRequest.scope.flatMap { s -> IDPConfig.config.claimMappings?.credentialTypesForScope(s) ?: setOf() }.toSet().mapIndexed {
          index, s -> InputDescriptor(index.toString(), constraints = InputDescriptorConstraints(
            fields = listOf(InputDescriptorField(listOf("$.type"), "1", null, mapOf("const" to s)))
          ), group = setOf("A"))
        }, submission_requirements = listOf(SubmissionRequirement(SubmissionRequirementRule.all, from = "A"))
      ))
  }

  fun initOIDCSession(authRequest: AuthorizationRequest): OIDCSession {
    //val vpTokenClaim = generateVpTokenClaim(authRequest)
    val nftClaim = NFTManager.generateNftClaim(authRequest)
    //val walletId = authRequest.customParameters["walletId"]?.firstOrNull() ?: VerifierConfig.config.wallets.values.map { wc -> wc.id }.firstOrNull() ?: throw InternalServerErrorResponse("Known wallets not configured")
    val walletId = "NFTswallet"
    val wallet = VerifierConfig.config.wallets[walletId] ?: throw BadRequestResponse("No wallet configuration found for given walletId")

    return OIDCSession(
      id = UUID.randomUUID().toString(),
      authRequest = authRequest,
      //vpTokenClaim = vpTokenClaim,
      NFTClaim= nftClaim,
      wallet = wallet
    ).also {
      sessionCache.put(it.id, it)
    }
  }

  fun getOIDCSession(id: String): OIDCSession? {
    return sessionCache.getIfPresent(id.replaceFirst("urn:ietf:params:oauth:request_uri:",""))
  }

  fun updateOIDCSession(session: OIDCSession) {
    sessionCache.put(session.id, session)
  }

  fun checkClientCompatibility(clientMetadata: ClientMetadata): Boolean {
    val oidcMeta = oidcProviderMetadata
    return clientMetadata.scope?.all { oidcMeta.scopes.contains(it) } ?: true &&
           clientMetadata.grantTypes?.all { oidcMeta.grantTypes.contains(it) } ?: true &&
           clientMetadata.responseTypes?.all { oidcMeta.responseTypes.contains(it) } ?: true &&
           clientMetadata.tokenEndpointAuthMethod?.let { oidcMeta.tokenEndpointAuthMethods.contains(it) } ?: true
  }

  private const val oidcApiPath: String = "api/oidc"
  private val oidcApiUrl: String get() = "${IDPConfig.config.externalUrl}/$oidcApiPath"

  fun getWalletRedirectionUri(session: OIDCSession): URI {

    val siopReq = VerifierManager.getService().newRequest(
      tokenClaim = session.vpTokenClaim!!,
      state = SIOPState(IDP_TYPE, session.id).encode()
    )
    return URI.create("${session.wallet.url}/${session.wallet.presentPath}?${siopReq.toUriQueryString()}")
    return URI.create("${session.wallet.url}?session=${session.id}&redirect_uri=http://localhost:8080/api/nft/callback")
  }

  fun getIdTokenFor(session: OIDCSession): String {
    return idTokenProvider.generateToken(session)
  }

  fun getAccessTokenFor(session: OIDCSession): AccessToken {
    return BearerAccessToken(
      accessTokenProvider.generateToken(session),
      EXPIRATION_TIME.seconds,
      Scope(OIDCScopeValue.OPENID)
    )
  }

  fun getTokensFor(code: String, redirect_uri: String): OIDCTokenResponse {
    val session = getOIDCSession(code) ?: throw BadRequestResponse("Invalid authorization code")
    if(!session.authRequest.redirectionURI.equals(URI.create(redirect_uri)))
      throw ForbiddenResponse("Redirection URI doesn't match OIDC session for given code")
    return OIDCTokenResponse(
      OIDCTokens(
        getIdTokenFor(session),
        getAccessTokenFor(session),
        RefreshToken()
      )
    )
  }

  val accessTokenProvider = JWTProvider(
    jwtAlgorithm,
    { session: OIDCSession, alg: Algorithm? ->
      JWT.create().withKeyId(keyId.id).withSubject(session.id).withAudience(session.authRequest.clientID.value).sign(alg)
    },
    JWT.require(jwtAlgorithm).build()
  )

  val idTokenProvider = JWTProvider(
    jwtAlgorithm,
    { session: OIDCSession, alg: Algorithm? ->
      JWT.create()
        .withKeyId(keyId.id)
        .withSubject(session.verificationResult!!.siopResponseVerificationResult!!.subject)
        .withIssuer("${IDPConfig.config.externalUrl}/api/oidc")
        .withIssuedAt(Date())
        .withAudience(session.authRequest.clientID.value)
        .apply {
          session.authRequest.customParameters["nonce"]?.firstOrNull()?.let { withClaim("nonce", it) }
          if(session.authRequest.responseType == ResponseType.IDTOKEN) {
            // add full user info to id_token, if implicit flow, with id_token only
            withPayload(getUserInfo(session).toJSONObject())
          } else if(session.authRequest.customParameters.containsKey("claims")) {
            session.authRequest.customParameters["claims"]?.firstOrNull()?.let {
              OIDCClaimsRequest.parse(it)
            }?.let { claims ->
              claims.idTokenClaimsRequest?.getClaimNames(false)?.let { idTokenClaims ->
                val userInfo = getUserInfo(session).toJSONObject()
                withPayload(userInfo.filterKeys { k -> idTokenClaims.contains(k) })
              }
            }
          }
        }
        .sign(alg)
    },
    JWT.require(jwtAlgorithm).build()
  )

  fun authorizeClient(clientID: String, clientSecret: String): Boolean {
    return OIDCClientRegistry.getClient(clientID).map { clientInfo ->
      clientInfo.id.value == clientID && clientInfo.secret.value == clientSecret && !clientInfo.secret.expired()
    }.orElse(false)
  }

  fun verifyClientRedirectUri(clientID: String, redirectUri: String): Boolean {
    return OIDCClientRegistry.getClient(clientID).map { clientInfo ->
      clientInfo.id.value == clientID && (clientInfo.metadata.redirectionURIStrings.contains(redirectUri) || clientInfo.metadata.customFields[OIDCClientRegistry.ALL_REDIRECT_URIS]?.toString().toBoolean())
    }.orElse(false)
  }

  fun decodeAccessToken(decodedJWT: DecodedJWT): OIDCSession {
    val session = sessionCache.getIfPresent(decodedJWT.subject) ?: throw JWTDecodeException("Invalid oidc session id")
    if(!decodedJWT.audience.contains(session.authRequest.clientID.value)) throw JWTDecodeException("Invalid audience for session")
    return session
  }

  private fun populateUserInfoClaims(claimBuilder: JWTClaimsSet.Builder, session: OIDCSession) {
    //update to add nft metadata in token user claims
    if(session.verificationResult?.siopResponseVerificationResult!=null && session.verificationResult?.siopResponseVerificationResult?.vp_token == null) throw BadRequestResponse("No vp_token received from SIOP response")

    if(session.verificationResult?.siopResponseVerificationResult!=null && session.verificationResult?.siopResponseVerificationResult?.vp_token == null) {
      // populate vp_token claim, if specifically requested in auth request
      if (OIDCUtils.getVCClaims(session.authRequest).vp_token != null) {
        claimBuilder.claim(
          "vp_token",
          session.verificationResult!!.siopResponseVerificationResult!!.vp_token!!.encode()
        )
      }

      // populate claims based on OIDC Scope, and/or claims requested in auth request
      (session.authRequest.scope?.flatMap { s -> IDPConfig.config.claimMappings?.mappingsForScope(s) ?: listOf() }
        ?: listOf())
        .plus(session.authRequest.customParameters["claims"]?.flatMap { c ->
          IDPConfig.config.claimMappings?.mappingsForClaim(
            c
          ) ?: listOf()
        } ?: listOf())
        .toSet().forEach { m ->
          val credential =
            session.verificationResult!!.siopResponseVerificationResult?.vp_token!!.verifiableCredential.firstOrNull { c ->
              c.type.contains(m.credentialType)
            } ?: throw BadRequestResponse("vp_token from SIOP resposne doesn't contain required credentials")
          val jp = JsonPath.parse(credential.json)
          val value = m.valuePath.split(" ").map { jp.read<Any>(it) }.joinToString(" ")
          claimBuilder.claim(m.claim, value)
        }
    }

    if(session.verificationResult?.nftresponseVerificationResult != null) {
      claimBuilder.claim("account", session.verificationResult?.nftresponseVerificationResult!!.account)
    }
    // populate claims based on OIDC Scope, and/or claims requested in auth request
    (session.authRequest.scope?.flatMap { s -> IDPConfig.config.claimMappings?.mappingsForScope(s) ?: listOf() } ?: listOf())
      .plus(session.authRequest.customParameters["claims"]?.flatMap { c -> IDPConfig.config.claimMappings?.mappingsForClaim(c) ?: listOf() } ?: listOf())
      .toSet().forEach { m ->
        val credential = session.verificationResult!!.vp_token!!.verifiableCredential.firstOrNull{ c -> c.type.contains(m.credentialType) } ?: throw BadRequestResponse("vp_token from SIOP response doesn't contain required credentials")
        val jp = JsonPath.parse(credential.json)
        val value = m.valuePath.split(" ").map { jp.read<Any>(it) }.joinToString(" ")
        claimBuilder.claim(m.claim, value)
      }
  }

  fun getUserInfo(session: OIDCSession): UserInfo {
    val verificationResult = session.verificationResult ?: throw BadRequestResponse("SIOP request not yet verified")
    val claimBuilder = JWTClaimsSet.Builder().subject(verificationResult.siopResponseVerificationResult!!.subject)
    populateUserInfoClaims(claimBuilder, session)
    return UserInfo(
      claimBuilder.build()
    )
  }

  private fun errorDescriptionFor(verificationResult: SIOPResponseVerificationResult): String {
    verificationResult.subject ?: return "Subject not defined"
    verificationResult.request ?: return "No SIOP request defined"
    if(!verificationResult.id_token_valid) return "Invalid id_token"
    val vpVerificationResult = verificationResult.verification_result ?: return "Verifiable presentation not verified"
    if(!vpVerificationResult.valid) return "Verifiable presentation invalid: $vpVerificationResult"
    return "Invalid SIOP response verification result"
  }

  private fun generateAuthSuccessResponseFor(session: OIDCSession): String {
    return session.authRequest.responseType.joinToString("&", postfix = "&state=${session.authRequest.state}") { rt ->
      when (rt) {
        ResponseType.Value.CODE -> "code=${session.id}"
        OIDCResponseTypeValue.ID_TOKEN -> "id_token=${getIdTokenFor(session)}"
        ResponseType.Value.TOKEN -> "access_token=${getAccessTokenFor(session).value}"
        else -> throw BadRequestResponse("Unsupported response_type: ${rt.value}")
      }
    }
  }

  private fun fragmentOrQuery(session: OIDCSession) =
    when(session.authRequest.impliedResponseMode()) {
      ResponseMode.FRAGMENT -> "#"
      else -> "?"
    }

  override fun continueIDPSessionForSIOPResponse(sessionId: String, verificationResult: SIOPResponseVerificationResult): URI {
    //make new class ResponseVerificationResult that handle SIOP or NFT verification based on session data
    //no modification on that function. Just, SIOPResponseVerificationResult -> ResponseVerificationResult
    val session = getOIDCSession(sessionId) ?: throw BadRequestResponse("OIDC session invalid or expired")
    if(verificationResult.isValid) {
      session.verificationResult = ResponseVerificationResult(verificationResult)
      updateOIDCSession(session)
      return URI.create(
        "${session.authRequest.redirectionURI}" +
        fragmentOrQuery(session) +
        generateAuthSuccessResponseFor(session)
      )
    } else {
      return URI.create(
        "${session.authRequest.redirectionURI}" +
        fragmentOrQuery(session) +
        "error=invalid_request" +
        "&error_description=${URLEncoder.encode(errorDescriptionFor(verificationResult), StandardCharsets.UTF_8)}" +
        "&state=${session.authRequest.state}"
      )
    }
  }

  fun continueIDPSessionResponse(sessionId: String, verificationResult: ResponseVerificationResult): URI {
    val session = getOIDCSession(sessionId) ?: throw BadRequestResponse("OIDC session invalid or expired")
    if(verificationResult.isValid) {
      session.verificationResult = verificationResult
      updateOIDCSession(session)
      return URI.create(
        "${session.authRequest.redirectionURI}" +
                fragmentOrQuery(session) +
                generateAuthSuccessResponseFor(session)
      )
    } else {
      val error= when(verificationResult.siopResponseVerificationResult){
        null-> "You don't have a NFT in our collection"
        else -> errorDescriptionFor(verificationResult.siopResponseVerificationResult!!)
      }
      return URI.create(
        "${session.authRequest.redirectionURI}" +
                fragmentOrQuery(session) +
                "error=invalid_request" +
                "&error_description=${URLEncoder.encode(error, StandardCharsets.UTF_8)}" +
                "&state=${session.authRequest.state}"
      )
    }
  }

  override val IDP_TYPE = IDPType.OIDC
}
