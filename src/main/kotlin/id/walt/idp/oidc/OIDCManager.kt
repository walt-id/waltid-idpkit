package id.walt.idp.oidc

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.interfaces.DecodedJWT
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.openid.connect.sdk.*
import com.nimbusds.openid.connect.sdk.claims.UserInfo
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.token.OIDCTokens
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.idp.IDPManager
import id.walt.idp.IDPType
import id.walt.idp.config.IDPConfig
import id.walt.idp.config.NFTClaimMapping
import id.walt.idp.config.NFTConfig
import id.walt.idp.context.ContextFactory
import id.walt.idp.context.ContextId
import id.walt.idp.nfts.ChainEcosystem
import id.walt.idp.nfts.NFTManager
import id.walt.idp.nfts.NftTokenClaim
import id.walt.idp.siop.SIOPState
import id.walt.idp.siwe.SiweManager
import id.walt.idp.util.WaltIdAlgorithm
import id.walt.model.dif.*
import id.walt.multitenancy.TenantId
import id.walt.services.context.ContextManager
import id.walt.services.key.KeyFormat
import id.walt.services.key.KeyService
import id.walt.services.keystore.KeyType
import id.walt.services.oidc.OIDCUtils
import id.walt.siwe.configuration.SiweSession
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.VerifierManager
import id.walt.verifier.backend.VerifierTenant
import id.walt.verifier.backend.WalletConfiguration
import id.walt.webwallet.backend.context.WalletContextManager
import io.javalin.http.BadRequestResponse
import io.javalin.http.ForbiddenResponse
import javalinjwt.JWTProvider
import mu.KotlinLogging
import java.net.URI
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.*
import java.util.concurrent.*

object OIDCManager : IDPManager {
    const val NEW_CLIENT_REGISTRATION_ID = "_IDP_KIT_NEW_CLIENT_"
    val EXPIRATION_TIME: Duration = Duration.ofMinutes(5)

    private val sessionCache: Cache<String, OIDCSession> =
        CacheBuilder.newBuilder().expireAfterAccess(EXPIRATION_TIME.seconds, TimeUnit.SECONDS).build()


    private val log = KotlinLogging.logger {}

    enum class AuthorizationMode {
        SIOP,
        NFT,
        SIWE,
    }

    val oidcContext
        get() = ContextFactory.getContextFor(ContextId.OIDC)

    val verifierManager
        get() = VerifierManager.getService()

    public val walletChooser = WalletConfiguration(
        "wallet-chooser",
        "",
        "sharecredential",
        "", ""
    )

    public val xDeviceWallet = WalletConfiguration(
        id = "x-device",
        url = "openid://",
        presentPath = "",
        receivePath = "",
        description = "cross device"
    )

    private lateinit var keyId: KeyId
    private lateinit var jwtAlgorithm: Algorithm
    lateinit var keySet: JWKSet

    init {
        WalletContextManager.runWith(oidcContext) {
            keyId = if (IDPConfig.config.keyId.isNotEmpty()) {
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

    val oidcProviderMetadata
        get() = OIDCProviderMetadata(
            Issuer(OIDCApiUrl),
            listOf(SubjectType.PUBLIC),
            URI.create("$OIDCApiUrl/jwkSet")
        ).apply {
            authorizationEndpointURI = URI.create("$OIDCApiUrl/authorize")
            pushedAuthorizationRequestEndpointURI = URI.create("$OIDCApiUrl/par")
            tokenEndpointURI = URI.create("$OIDCApiUrl/token")
            userInfoEndpointURI = URI.create("$OIDCApiUrl/userInfo")
            registrationEndpointURI = URI.create("$OIDCApiUrl/clients/register")
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE)
            responseTypes = listOf(
                ResponseType.CODE,
                ResponseType.IDTOKEN,
                ResponseType.TOKEN,
                ResponseType.CODE_IDTOKEN,
                ResponseType.CODE_TOKEN,
                ResponseType.IDTOKEN_TOKEN,
                ResponseType.CODE_IDTOKEN_TOKEN
            )
            claims = listOf(
                "vp_token",
                *(IDPConfig.config.claimConfig?.allMappings()?.map { m -> m.claim }?.toSet() ?: setOf()).toTypedArray()
            )
            scopes = Scope(
                "openid",
                *(IDPConfig.config.claimConfig?.allMappings()?.flatMap { m -> m.scope }?.toSet() ?: setOf()).toTypedArray()
            )
            setCustomParameter("wallets_supported", ContextManager.runWith(verifierManager.getVerifierContext(TenantId.DEFAULT_TENANT)) {
                VerifierTenant.config.wallets.values.map { wallet ->
                    mapOf(
                        "id" to wallet.id,
                        "description" to wallet.description
                    )
                }
            })
            tokenEndpointAuthMethods = listOf(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        }

    private fun getAuthorizationModeFor(authRequest: AuthorizationRequest): AuthorizationMode {
        if ((OIDCUtils.getVCClaims(authRequest).vp_token != null)
            || authRequest.scope.contains("vp_token")
            || authRequest.scope.any {
                (IDPConfig.config.claimConfig?.mappingsForScope(it)
                    ?.count { m -> m.authorizationMode == AuthorizationMode.SIOP } ?: 0) > 0
            }
        ) {
            return AuthorizationMode.SIOP
        } else if ((NFTManager.getNFTClaims(authRequest).nft_token != null)
            || authRequest.scope.contains("nft_token")
            || authRequest.scope.any {
                (IDPConfig.config.claimConfig?.mappingsForScope(it)
                    ?.count { m -> m.authorizationMode == AuthorizationMode.NFT } ?: 0) > 0
            }
        ) {
            return AuthorizationMode.NFT
        } else if (authRequest.scope.contains("siwe")) {
            return AuthorizationMode.SIWE
        }
        return IDPConfig.config.fallbackAuthorizationMode
    }

    private fun generatePresentationDefinition(authRequest: AuthorizationRequest): PresentationDefinition {
        // TODO: adapt for updated OIDC4VP flow??
        val presentationDefinition =
            OIDCUtils.getVCClaims(authRequest).vp_token?.presentation_definition ?: PresentationDefinition(
                id = "1",
                input_descriptors = authRequest.scope.flatMap { s ->
                    IDPConfig.config.claimConfig?.credentialTypesForScope(s) ?: setOf()
                }.toSet().mapIndexed { index, s ->
                    InputDescriptor(
                        index.toString(), constraints = InputDescriptorConstraints(
                            fields = listOf(InputDescriptorField(listOf("$.type"), "1", null, mapOf("const" to s)))
                        ), group = setOf("A")
                    )
                }, submission_requirements = listOf(SubmissionRequirement(SubmissionRequirementRule.all, from = "A"))
            )
        if (presentationDefinition.input_descriptors.isEmpty()) {
            // TODO: adapt for updated OIDC4VP flow??
            return IDPConfig.config.claimConfig?.default_vp_token_claim?.presentation_definition ?: presentationDefinition
        }
        return presentationDefinition
    }

    private fun generateNftClaim(authRequest: AuthorizationRequest): NftTokenClaim {
        if (NFTManager.getNFTClaims(authRequest).nft_token != null) {
            return NFTManager.getNFTClaims(authRequest).nft_token!!
        } else {
            val nftClaimFromMappings = authRequest.scope.flatMap { s ->
                IDPConfig.config.claimConfig?.mappingsForScope(s)?.filterIsInstance<NFTClaimMapping>()
                    ?: listOf()
            }
                .map { m -> NftTokenClaim(
                  ecosystems = m.claimMappings.keys.map { ChainEcosystem.valueOf(it) }.toSet(),
                  nftTokenContraints = m.claimMappings.mapValues { entry -> entry.value.nftTokenConstraint }
                ) }
            if (nftClaimFromMappings.size > 1) {
                throw BadRequestResponse("Ambiguous NFT authorization request")
            }
            if (nftClaimFromMappings.isNotEmpty()) {
                return nftClaimFromMappings.first()
            }
        }
        return IDPConfig.config.claimConfig?.default_nft_token_claim
            ?: throw BadRequestResponse("No nft token claim defined for this authorization request")
    }

    private  fun convertUUIDToBytes(uuid: UUID): ByteArray?{
        val bb: ByteBuffer = ByteBuffer.wrap(ByteArray(16))
        bb.putLong(uuid.mostSignificantBits)
        bb.putLong(uuid.leastSignificantBits)
        return bb.array()
    }

    fun initOIDCSession(authRequest: AuthorizationRequest): OIDCSession {
        val authorizationMode = getAuthorizationModeFor(authRequest)

        return OIDCSession(
            id = UUID.randomUUID().toString(),
            authRequest = authRequest,
            authorizationMode = authorizationMode,
            nonce = Base64URL.encode(convertUUIDToBytes(UUID.randomUUID())).toString(),
            presentationDefinition = when (authorizationMode) {
                AuthorizationMode.SIOP -> generatePresentationDefinition(authRequest)
                else -> null
            },
            nftTokenClaim = when (authorizationMode) {
                AuthorizationMode.NFT -> generateNftClaim(authRequest)
                else -> null
            },
            wallet = when (authorizationMode) {
                AuthorizationMode.SIOP -> ContextManager.runWith(verifierManager.getVerifierContext(TenantId.DEFAULT_TENANT)) {
                    authRequest.customParameters["walletId"]?.map { VerifierTenant.config.wallets[it] }?.firstOrNull()
                        ?: walletChooser
                }

                AuthorizationMode.NFT -> NFTConfig.config.nftWallet
                AuthorizationMode.SIWE -> NFTConfig.config.nftWallet
            },
            siweSession = when (authorizationMode) {
                AuthorizationMode.NFT -> SiweSession(nonce = UUID.randomUUID().toString())
                AuthorizationMode.SIWE -> SiweSession(nonce = UUID.randomUUID().toString())
                else -> null
            }
        ).also {
            sessionCache.put(it.id, it)
        }
    }

    fun getOIDCSession(id: String): OIDCSession? {
        return sessionCache.getIfPresent(id.replaceFirst("urn:ietf:params:oauth:request_uri:", ""))
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

    private const val OIDC_API_PATH: String = "api/oidc"
    val OIDCApiUrl: String get() = "${IDPConfig.config.externalUrl}/$OIDC_API_PATH"

    fun getWalletRedirectionUri(session: OIDCSession, selectedWallet: WalletConfiguration? = null): URI {
        val wallet = selectedWallet ?: session.wallet
        return when (session.authorizationMode) {
            AuthorizationMode.SIOP -> ContextManager.runWith(verifierManager.getVerifierContext(TenantId.DEFAULT_TENANT)) {
                val walletUrl = URI.create("${wallet.url}/${wallet.presentPath}")
                if(wallet.id == walletChooser.id){
                    URI.create("${walletUrl}?state=${SIOPState(idpType, session.id).encode()}")
                } else {
                    val siopReq = verifierManager.newRequest(
                        walletUrl = walletUrl,
                        presentationDefinition = session.presentationDefinition!!,
                        //state = session.id
                        state = SIOPState(idpType, session.id).encode(),
                        responseMode = if(wallet.id == xDeviceWallet.id) ResponseMode("post") else ResponseMode.FORM_POST,
                        nonce = session.nonce
                    )
                    siopReq.toURI()
                }
            }

            AuthorizationMode.NFT -> {
                URI.create("${wallet.url}?session=${session.id}&nonce=${session.siweSession?.nonce}&redirect_uri=${NFTManager.NFTApiUrl}/callback")
            }

            AuthorizationMode.SIWE -> {
                URI.create("${wallet.url}?session=${session.id}&nonce=${session.siweSession?.nonce}&redirect_uri=${SiweManager.SIWEApiUrl}/callback")
            }
        }
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
        if (!session.authRequest.redirectionURI.equals(URI.create(redirect_uri)))
            throw ForbiddenResponse("Redirection URI doesn't match OIDC session for given code")
        return OIDCTokenResponse(
            OIDCTokens(
                getIdTokenFor(session),
                getAccessTokenFor(session),
                RefreshToken()
            )
        )
    }

    fun getSubjectFor(session: OIDCSession): String {
        return when (session.authorizationMode) {
            AuthorizationMode.SIOP -> session.verificationResult!!.siopResponseVerificationResult!!.subject!!
            AuthorizationMode.NFT -> session.verificationResult!!.nftresponseVerificationResult!!.account
            AuthorizationMode.SIWE -> session.verificationResult!!.siweResponseVerificationResult!!.account
        }
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
                .withSubject(getSubjectFor(session))
                .withIssuer("${IDPConfig.config.externalUrl}/api/oidc")
                .withIssuedAt(Date())
                .withAudience(session.authRequest.clientID.value)
                .apply {
                    session.authRequest.customParameters["nonce"]?.firstOrNull()?.let { withClaim("nonce", it) }
                    if (session.authRequest.responseType == ResponseType.IDTOKEN) {
                        // add full user info to id_token, if implicit flow, with id_token only
                        withPayload(getUserInfo(session).toJSONObject())
                    } else if (session.authRequest.customParameters.containsKey("claims")) {
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

    val clientRegistrationTokenProvider = JWTProvider(
        jwtAlgorithm,
        { clientID: String, alg: Algorithm? ->
            JWT.create().withKeyId(keyId.id).withSubject(clientID).sign(alg)
        },
        JWT.require(jwtAlgorithm).build()
    )

    fun authorizeClient(clientID: String, clientSecret: String): Boolean {
        log.debug { "Trying to authorize clientId $clientID" }
        return OIDCClientRegistry.getClient(clientID).map { clientInfo ->
            log.debug { "clientInfoId: ${clientInfo.id.value}, clientId: $clientID" }
            log.debug { "clientsecret: ${clientInfo.secret.value}, clientSecret: $clientSecret" }
            clientInfo.id.value == clientID && clientInfo.secret.value == clientSecret && !clientInfo.secret.expired()
        }.orElse(false)
    }

    fun verifyClientRedirectUri(clientID: String, redirectUri: String): Boolean {
        return OIDCClientRegistry.getClient(clientID).map { clientInfo ->
            //clientInfo.metadata.redirect
            clientInfo.id.value == clientID && (clientInfo.metadata.redirectionURIStrings.contains(redirectUri) || clientInfo.metadata.customFields[OIDCClientRegistry.ALL_REDIRECT_URIS]?.toString()
                .toBoolean())
        }.orElse(false)
    }

    fun decodeAccessToken(decodedJWT: DecodedJWT): OIDCSession {
        val session = sessionCache.getIfPresent(decodedJWT.subject) ?: throw JWTDecodeException("Invalid oidc session id")
        if (!decodedJWT.audience.contains(session.authRequest.clientID.value)) throw JWTDecodeException("Invalid audience for session")
        return session
    }

    private fun populateUserInfoClaims(claimBuilder: JWTClaimsSet.Builder, session: OIDCSession) {
        //update to add nft metadata in token user claims
        if (session.verificationResult?.isValid != true) throw BadRequestResponse("No valid verification available for this session")

        if (session.authorizationMode == AuthorizationMode.SIOP) {
            // populate vp_token claim, if specifically requested in auth request
            // TODO: adapt for updated OIDC4VP spec, consider response_type vp_token
            if (OIDCUtils.getVCClaims(session.authRequest).vp_token != null ||
                session.authRequest.scope.contains("vp_token") ||
                session.authRequest.customParameters["claims"]?.contains("vp_token") == true
            ) {
                claimBuilder.claim(
                    "vp_token",
                    session.verificationResult!!.siopResponseVerificationResult!!.vps.map { it.vp.encode() }.toList()
                )
            }
        } else if (session.authorizationMode == AuthorizationMode.NFT) {
            claimBuilder.claim("account", session.verificationResult!!.nftresponseVerificationResult!!.account)
            if (NFTManager.getNFTClaims(session.authRequest).nft_token != null ||
                session.authRequest.scope.contains("nft_token") ||
                session.authRequest.customParameters["claims"]?.contains("nft_token") == true
            ) {
                claimBuilder.claim("nft_token", session.verificationResult!!.nftresponseVerificationResult!!.metadata)
            }
        }

        // populate claims based on OIDC Scope, and/or claims requested in auth request
        (session.authRequest.scope?.flatMap { s -> IDPConfig.config.claimConfig?.mappingsForScope(s) ?: listOf() } ?: listOf())
            .plus(session.authRequest.customParameters["claims"]?.flatMap { c ->
                IDPConfig.config.claimConfig?.mappingsForClaim(
                    c
                ) ?: listOf()
            } ?: listOf())
            .toSet().forEach { m ->
                // fill claims based on claim mapping
                m.fillClaims(session.verificationResult!!, claimBuilder)
            }
    }

    fun getUserInfo(session: OIDCSession): UserInfo {
        session.verificationResult ?: throw BadRequestResponse("Auth request not yet verified")
        val claimBuilder = JWTClaimsSet.Builder().subject(getSubjectFor(session))
        populateUserInfoClaims(claimBuilder, session)
        return UserInfo(
            claimBuilder.build()
        )
    }

    private fun errorDescriptionFor(verificationResult: SIOPResponseVerificationResult): String {
        verificationResult.subject ?: return "Subject not defined"
        if (!verificationResult.isValid) return "Verifiable presentation invalid"
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
        when (session.authRequest.impliedResponseMode()) {
            ResponseMode.FRAGMENT -> "#"
            else -> "?"
        }

    override fun continueIDPSessionForSIOPResponse(sessionId: String, verificationResult: SIOPResponseVerificationResult): URI {
        //make new class ResponseVerificationResult that handle SIOP or NFT verification based on session data
        //no modification on that function. Just, SIOPResponseVerificationResult -> ResponseVerificationResult
        val session = getOIDCSession(sessionId) ?: throw BadRequestResponse("OIDC session invalid or expired")
        if (verificationResult.isValid) {
            log.debug { "Verification result: OVERALL VALID!" }
            session.verificationResult = ResponseVerificationResult(verificationResult)
            updateOIDCSession(session)
            val uri = URI.create(
                "${session.authRequest.redirectionURI}" +
                        fragmentOrQuery(session) +
                        generateAuthSuccessResponseFor(session)
            ).also { log.debug { "CREATED URI: $it" } }
            println(uri)
            return uri
        } else {
            log.debug { "Verification result: OVERALL INVALID!" }
            return URI.create(
                "${session.authRequest.redirectionURI}" +
                        fragmentOrQuery(session) +
                        "error=invalid_request" +
                        "&error_description=${
                            URLEncoder.encode(
                                errorDescriptionFor(verificationResult),
                                StandardCharsets.UTF_8
                            )
                        }" +
                        "&state=${session.authRequest.state}"
            )
        }
    }

    fun continueIDPSessionResponse(sessionId: String, verificationResult: ResponseVerificationResult): URI {
        log.debug { "CONTINUE IDP SESSION RESPONSE: $sessionId" }
        val session = getOIDCSession(sessionId) ?: throw BadRequestResponse("OIDC session invalid or expired")
        log.debug { "Session ID: ${session.id}" }
        if (verificationResult.isValid) {
            log.debug { "Verification result: OVERALL VALID!" }
            session.verificationResult = verificationResult
            updateOIDCSession(session)
            return URI.create(
                "${session.authRequest.redirectionURI}" +
                        fragmentOrQuery(session) +
                        generateAuthSuccessResponseFor(session)
            ).also { log.debug { "CREATED URI: $it" } }
        } else {
            log.debug { "Verification result: OVERALL INVALID!" }
            val error = when (session.authorizationMode) {
                AuthorizationMode.NFT -> verificationResult.nftresponseVerificationResult?.error
                AuthorizationMode.SIOP -> errorDescriptionFor(verificationResult.siopResponseVerificationResult!!)
                AuthorizationMode.SIWE -> verificationResult.siweResponseVerificationResult?.error
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

    override val idpType = IDPType.OIDC

    fun getClientRegistrationToken(clientID: String = NEW_CLIENT_REGISTRATION_ID): String {
        return clientRegistrationTokenProvider.generateToken(clientID)
    }
}
