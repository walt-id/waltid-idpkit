package id.walt.idp

import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.util.URLUtils
import com.nimbusds.openid.connect.sdk.*
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.common.KlaxonWithConverters
import id.walt.credentials.w3c.templates.VcTemplateManager
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.credentials.w3c.toVerifiablePresentation
import id.walt.custodian.Custodian
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCClientRegistry
import id.walt.idp.oidc.OIDCManager
import id.walt.model.DidMethod
import id.walt.model.dif.InputDescriptor
import id.walt.model.dif.PresentationDefinition
import id.walt.model.dif.VCSchema
import id.walt.model.oidc.VCClaims
import id.walt.model.oidc.VpTokenClaim
import id.walt.services.did.DidService
import id.walt.services.oidc.OIDC4VPService
import id.walt.services.oidc.OIDCUtils
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.verifier.backend.PresentationRequestInfo
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.VerifierTenant
import id.walt.verifier.backend.WalletConfiguration
import io.javalin.http.HttpCode
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.maps.shouldContainKey
import io.kotest.matchers.maps.shouldNotContainKey
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockkObject
import java.net.URI
import java.nio.file.Path
import java.util.*

class OIDCTest : OIDCTestBase() {

    private lateinit var DID: String
    private lateinit var VC: String
    private val APP_REDIRECT: URI = URI.create("http://app")
    private val CLIENT_ID = "test-client"
    private val CLIENT_SECRET = "test-secret"

    override fun customInit() {
        mockkObject(OIDCClientRegistry)
        every { OIDCClientRegistry.load(CLIENT_ID) } returns Optional.of(
            ClientInformation(
                ClientID(CLIENT_ID), Date(),
                ClientMetadata().apply {
                    redirectionURI = APP_REDIRECT
                }, Secret(CLIENT_SECRET)
            )
        )

        DID = DidService.create(DidMethod.key)
     //   VC = Signatory.getService().issue("VerifiableId", ProofConfig(DID, DID, proofType = ProofType.LD_PROOF))
    }


    private fun simulateAuthReqToAppRedirect(
        authReq: AuthorizationRequest,
        oidcMeta: OIDCProviderMetadata
    ): URI {

        oidcMeta.scopes shouldContain OIDCScopeValue.OPENID
        oidcMeta.scopes shouldContainAll authReq.scope
        oidcMeta.claims shouldContain "vp_token"

        // APP: init oidc session (par request)
        val parHTTPResponse =
            PushedAuthorizationRequest(oidcMeta.pushedAuthorizationRequestEndpointURI, authReq).toHTTPRequest().apply {
                authorization = ClientSecretBasic(ClientID(CLIENT_ID), Secret(CLIENT_SECRET)).toHTTPAuthorizationHeader()
            }.send()

        parHTTPResponse.statusCode shouldBe HttpCode.CREATED.status

        val parResponse = PushedAuthorizationResponse.parse(parHTTPResponse)

        // APP: redirect to authorization endpoint on IDP
        val authHttpResponse = AuthorizationRequest.Builder(parResponse.toSuccessResponse().requestURI, ClientID(CLIENT_ID))
            .endpointURI(oidcMeta.authorizationEndpointURI)
            .build().toHTTPRequest().apply {
                followRedirects = false
            }.send()

        // IDP: redirects to IDPKIT WALLET CONNECT PAGE
        authHttpResponse.statusCode shouldBe HttpCode.FOUND.status
        authHttpResponse.location.path shouldBe "/${OIDCManager.walletChooser.presentPath}"
        val state = URLUtils.parseParameters(authHttpResponse.location.query).get("state")?.firstOrNull()
        state shouldNotBe null

        // IDPKIT WALLET CONNECT PAGE: redirect to wallet
        val requestInfoResponse = HTTPRequest(HTTPRequest.Method.GET,
            URI.create("${IDPConfig.config.externalUrl}/api/oidc/web-api/getWalletRedirectAddress?walletId=x-device&state=${state!!}")).send()
        requestInfoResponse.indicatesSuccess() shouldBe true
        val requestInfo = KlaxonWithConverters().parse<PresentationRequestInfo>(requestInfoResponse.content)
        requestInfo shouldNotBe null

        // WALLET: parse SIOP request
        val siopReq = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(requestInfo!!.url))
        val presentationDef = shouldNotThrowAny { OIDC4VPService.getPresentationDefinition(siopReq) }
        presentationDef.input_descriptors shouldNot beEmpty()
        siopReq.customParameters shouldContainKey "nonce"

        // WALLET: fulfill SIOP request on IDP
        val presentation =
            Custodian.getService().createPresentation(
                listOf(VC),
                DID,
                challenge = siopReq.customParameters["nonce"]!!.first(),
                expirationDate = null
            )
                .toVerifiablePresentation()
        val siopResponse = OIDC4VPService.getSIOPResponseFor(siopReq, DID, listOf(presentation))

        // IDP: redirects to APP with authorization code
        return URI.create(OIDC4VPService.postSIOPResponse(siopReq, siopResponse))
    }
    @Ignore()
    @Test
    fun testGetVpTokenCodeFlow() {
        // APP: get oidc discovery document
        val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
        // APP: init oidc session (par request)
        val authReq = AuthorizationRequest.Builder(ResponseType.CODE, ClientID(CLIENT_ID))
            .scope(Scope(OIDCScopeValue.OPENID))
            .customParameter(
                "claims", VCClaims(
                    vp_token = VpTokenClaim(
                        PresentationDefinition(
                            "1",
                            listOf(
                                InputDescriptor(schema = VCSchema(uri = VcTemplateManager.getTemplate("VerifiableId", true).template!!.credentialSchema!!.id))
                            )
                        )
                    )
                ).toJSONString()
            )
            .state(State("TEST"))
            .redirectionURI(APP_REDIRECT)
            .build()

        // IDP: redirects to APP with authorization code
        val redirectToAPP = simulateAuthReqToAppRedirect(authReq, metadata)
        redirectToAPP.query shouldContain "state=TEST"
        redirectToAPP.query shouldContain "code="

        // APP: parse authorization code
        val code = OIDCUtils.getCodeFromRedirectUri(redirectToAPP)
        code shouldNotBe null

        // APP: get access token
        val tokenHttpResponse = TokenRequest(
            metadata.tokenEndpointURI,
            ClientID(CLIENT_ID),
            AuthorizationCodeGrant(AuthorizationCode(code), APP_REDIRECT)
        ).toHTTPRequest().apply {
            authorization = ClientSecretBasic(ClientID(CLIENT_ID), Secret(CLIENT_SECRET)).toHTTPAuthorizationHeader()
        }.send()
        val tokenResponse = OIDCTokenResponse.parse(tokenHttpResponse)

        tokenResponse.indicatesSuccess() shouldBe true
        tokenResponse.oidcTokens.idToken.jwtClaimsSet.claims shouldNotContainKey "vp_token"
        tokenResponse.oidcTokens.idToken.jwtClaimsSet.subject shouldBe DID

        // APP: get userInfo
        val userInfoHttpResponse =
            UserInfoRequest(metadata.userInfoEndpointURI, tokenResponse.toSuccessResponse().tokens.accessToken).toHTTPRequest()
                .send()
        userInfoHttpResponse.indicatesSuccess() shouldBe true

        val userInfoResponse = UserInfoResponse.parse(userInfoHttpResponse)
        userInfoResponse.toSuccessResponse().userInfo.subject.value shouldBe DID

        val vpToken = userInfoResponse.toSuccessResponse().userInfo.getStringListClaim("vp_token")
        vpToken shouldNotBe null
    }
    @Ignore()
    @Test
    fun testGetVpTokenInIdToken() {
        // APP: get oidc discovery document
        val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
        // APP: init oidc session (par request)
        val authReq = AuthorizationRequest.Builder(ResponseType.IDTOKEN, ClientID(CLIENT_ID))
            .scope(Scope(OIDCScopeValue.OPENID))
            .customParameter(
                "claims", VCClaims(
                    vp_token = VpTokenClaim(
                        PresentationDefinition(
                            "1",
                            listOf(
                                InputDescriptor(schema = VCSchema(uri = VcTemplateManager.getTemplate("VerifiableId", true).template!!.credentialSchema!!.id))
                            )
                        )
                    )
                ).toJSONString()
            )
            .state(State("TEST"))
            .redirectionURI(APP_REDIRECT)
            .build()

        // IDP: redirects to APP with authorization code
        val redirectToAPP = simulateAuthReqToAppRedirect(authReq, metadata)
        redirectToAPP.fragment shouldNotBe null
        redirectToAPP.fragment shouldContain "id_token="
        val authResp = AuthenticationResponseParser.parse(redirectToAPP)
        authResp.toSuccessResponse().idToken.jwtClaimsSet.subject shouldBe DID
        authResp.toSuccessResponse().idToken.jwtClaimsSet.claims shouldContainKey "vp_token"
    }

    @Ignore()
    @Test
    fun testGetProfileScopeCodeFlow() {
        // APP: get oidc discovery document
        val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
        // APP: init oidc session (par request)
        val authReq = AuthorizationRequest.Builder(ResponseType.CODE, ClientID(CLIENT_ID))
            .scope(Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE))
            .state(State("TEST"))
            .redirectionURI(APP_REDIRECT)
            .build()

        // IDP: redirects to APP with authorization code
        val redirectToAPP = simulateAuthReqToAppRedirect(authReq, metadata)
        redirectToAPP.query shouldContain "state=TEST"
        redirectToAPP.query shouldContain "code="

        // APP: parse authorization code
        val code = OIDCUtils.getCodeFromRedirectUri(redirectToAPP)
        code shouldNotBe null

        // APP: get access token
        val tokenHttpResponse = TokenRequest(
            metadata.tokenEndpointURI,
            ClientID(),
            AuthorizationCodeGrant(AuthorizationCode(code), APP_REDIRECT)
        ).toHTTPRequest().apply {
            authorization = ClientSecretBasic(ClientID(CLIENT_ID), Secret(CLIENT_SECRET)).toHTTPAuthorizationHeader()
        }.send()
        val tokenResponse = OIDCTokenResponse.parse(tokenHttpResponse)

        tokenResponse.indicatesSuccess() shouldBe true
        tokenResponse.oidcTokens.idToken.jwtClaimsSet.subject shouldBe DID

        // APP: get userInfo
        val userInfoHttpResponse =
            UserInfoRequest(metadata.userInfoEndpointURI, tokenResponse.toSuccessResponse().tokens.accessToken).toHTTPRequest()
                .send()
        userInfoHttpResponse.indicatesSuccess() shouldBe true

        val userInfoResponse = UserInfoResponse.parse(userInfoHttpResponse)
        userInfoResponse.toSuccessResponse().userInfo.subject.value shouldBe DID

        val verifiableId = VC.toVerifiableCredential()
        userInfoResponse.toSuccessResponse().userInfo.name shouldBe "${verifiableId.credentialSubject!!.properties["firstName"]} ${verifiableId.credentialSubject!!.properties["familyName"]}"
        userInfoResponse.toSuccessResponse().userInfo.givenName shouldBe verifiableId.credentialSubject!!.properties["firstName"]
        userInfoResponse.toSuccessResponse().userInfo.familyName shouldBe verifiableId.credentialSubject!!.properties["familyName"]
        userInfoResponse.toSuccessResponse().userInfo.birthdate shouldBe verifiableId.credentialSubject!!.properties["dateOfBirth"]
        userInfoResponse.toSuccessResponse().userInfo.gender.value shouldBe verifiableId.credentialSubject!!.properties["gender"]

    }

}
