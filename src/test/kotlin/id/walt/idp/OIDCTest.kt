package id.walt.idp

import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.*
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.custodian.Custodian
import id.walt.idp.oidc.OIDCClientRegistry
import id.walt.model.DidMethod
import id.walt.model.dif.InputDescriptor
import id.walt.model.dif.PresentationDefinition
import id.walt.model.dif.VCSchema
import id.walt.model.oidc.OIDCProvider
import id.walt.model.oidc.SIOPv2Request
import id.walt.model.oidc.VCClaims
import id.walt.model.oidc.VpTokenClaim
import id.walt.services.did.DidService
import id.walt.services.oidc.OIDC4VPService
import id.walt.services.oidc.OIDCUtils
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.vclib.credentials.VerifiableId
import id.walt.vclib.credentials.VerifiablePresentation
import id.walt.vclib.model.toCredential
import id.walt.vclib.templates.VcTemplateManager
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.WalletConfiguration
import io.javalin.http.HttpCode
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.maps.shouldContainKey
import io.kotest.matchers.maps.shouldNotContainKey
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockkObject
import java.net.URI
import java.util.*

class OIDCTest: OIDCTestBase() {

  private lateinit var DID: String
  private lateinit var VC: String
  private val APP_REDIRECT: URI = URI.create("http://app")
  private val CLIENT_ID = "test-client"
  private val CLIENT_SECRET = "test-secret"

  override fun customInit() {
    mockkObject(OIDCClientRegistry)
    every { OIDCClientRegistry.load(CLIENT_ID) } returns Optional.of(ClientInformation(ClientID(CLIENT_ID), Date(),
      ClientMetadata().apply {
        redirectionURI = APP_REDIRECT
    }, Secret(CLIENT_SECRET)))

    DID = DidService.create(DidMethod.key)
    VC = Signatory.getService().issue("VerifiableId", ProofConfig(DID, DID, proofType = ProofType.LD_PROOF))
  }


  private fun simulateAuthReqToAppRedirect(
    authReq: AuthorizationRequest,
    targetWallet: WalletConfiguration,
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

    // IDP: redirects to WALLET
    authHttpResponse.statusCode shouldBe HttpCode.FOUND.status
    authHttpResponse.location.authority shouldBe URI.create(targetWallet.url).authority
    authHttpResponse.location.path.trim('/') shouldBe targetWallet.presentPath.trim('/')

    // WALLET: parse SIOP request
    val authReq = AuthorizationRequest.parse(authHttpResponse.location)
    val vcClaims = OIDCUtils.getVCClaims(authReq)
    vcClaims.vp_token shouldNotBe null
    vcClaims.vp_token!!.presentation_definition shouldNotBe null

    // WALLET: fulfill SIOP request on IDP
    val siopReq = SIOPv2Request(
      redirect_uri = authReq.redirectionURI.toString(),
      response_mode = authReq.responseMode.value,
      nonce = authReq.customParameters["nonce"]!!.first(),
      claims = vcClaims,
      state = authReq.state.value
    )
    val vpSvc = OIDC4VPService(OIDCProvider("", ""))
    val presentation =
      Custodian.getService().createPresentation(listOf(VC), DID, challenge = siopReq.nonce, expirationDate = null)
        .toCredential() as VerifiablePresentation
    val siopResponse = vpSvc.getSIOPResponseFor(siopReq, DID, listOf(presentation))

    // IDP: redirects to APP with authorization code
    return URI.create(vpSvc.postSIOPResponse(siopReq, siopResponse))
  }

  @Test
  fun testGetVpTokenCodeFlow() {
    val targetWallet = VerifierConfig.config.wallets.values.first()
    // APP: get oidc discovery document
    val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
    // APP: init oidc session (par request)
    val authReq = AuthorizationRequest.Builder(ResponseType.CODE, ClientID(CLIENT_ID))
      .scope(Scope(OIDCScopeValue.OPENID))
      .customParameter("claims", VCClaims(
      vp_token = VpTokenClaim(PresentationDefinition( "1",
        listOf(
          InputDescriptor(schema = VCSchema(uri = VcTemplateManager.loadTemplate("VerifiableId").credentialSchema!!.id))
        )))
    ).toJSONString())
      .customParameter("walletId", targetWallet.id)
      .state(State("TEST"))
      .redirectionURI(APP_REDIRECT)
      .build()

    // IDP: redirects to APP with authorization code
    val redirectToAPP = simulateAuthReqToAppRedirect(authReq, targetWallet, metadata)
    redirectToAPP.query shouldContain "state=TEST"
    redirectToAPP.query shouldContain "code="

    // APP: parse authorization code
    val code = OIDCUtils.getCodeFromRedirectUri(redirectToAPP)
    code shouldNotBe null

    // APP: get access token
    val tokenHttpResponse = TokenRequest(metadata.tokenEndpointURI, ClientID(CLIENT_ID), AuthorizationCodeGrant(AuthorizationCode(code), APP_REDIRECT)).toHTTPRequest().apply {
      authorization = ClientSecretBasic(ClientID(CLIENT_ID), Secret(CLIENT_SECRET)).toHTTPAuthorizationHeader()
    }.send()
    val tokenResponse = OIDCTokenResponse.parse(tokenHttpResponse)

    tokenResponse.indicatesSuccess() shouldBe true
    tokenResponse.oidcTokens.idToken.jwtClaimsSet.claims shouldNotContainKey  "vp_token"
    tokenResponse.oidcTokens.idToken.jwtClaimsSet.subject shouldBe DID

    // APP: get userInfo
    val userInfoHttpResponse = UserInfoRequest(metadata.userInfoEndpointURI, tokenResponse.toSuccessResponse().tokens.accessToken).toHTTPRequest().send()
    userInfoHttpResponse.indicatesSuccess() shouldBe true

    val userInfoResponse = UserInfoResponse.parse(userInfoHttpResponse)
    userInfoResponse.toSuccessResponse().userInfo.subject.value shouldBe DID

    val vpToken = userInfoResponse.toSuccessResponse().userInfo.getStringClaim("vp_token")
    vpToken shouldNotBe null
  }

  @Test
  fun testGetVpTokenInIdToken() {
    val targetWallet = VerifierConfig.config.wallets.values.first()
    // APP: get oidc discovery document
    val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
    // APP: init oidc session (par request)
    val authReq = AuthorizationRequest.Builder(ResponseType.IDTOKEN, ClientID(CLIENT_ID))
      .scope(Scope(OIDCScopeValue.OPENID))
      .customParameter("claims", VCClaims(
        vp_token = VpTokenClaim(PresentationDefinition( "1",
          listOf(
            InputDescriptor(schema = VCSchema(uri = VcTemplateManager.loadTemplate("VerifiableId").credentialSchema!!.id))
          )))
      ).toJSONString())
      .customParameter("walletId", targetWallet.id)
      .state(State("TEST"))
      .redirectionURI(APP_REDIRECT)
      .build()

    // IDP: redirects to APP with authorization code
    val redirectToAPP = simulateAuthReqToAppRedirect(authReq, targetWallet, metadata)
    redirectToAPP.fragment shouldNotBe null
    redirectToAPP.fragment shouldContain "id_token="
    val authResp = AuthenticationResponseParser.parse(redirectToAPP)
    authResp.toSuccessResponse().idToken.jwtClaimsSet.subject shouldBe DID
    authResp.toSuccessResponse().idToken.jwtClaimsSet.claims shouldContainKey "vp_token"
  }


  @Test
  fun testGetProfileScopeCodeFlow() {
    val targetWallet = VerifierConfig.config.wallets.values.first()
    // APP: get oidc discovery document
    val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
    // APP: init oidc session (par request)
    val authReq = AuthorizationRequest.Builder(ResponseType.CODE, ClientID(CLIENT_ID))
      .scope(Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE))
      .customParameter("walletId", targetWallet.id)
      .state(State("TEST"))
      .redirectionURI(APP_REDIRECT)
      .build()

    // IDP: redirects to APP with authorization code
    val redirectToAPP = simulateAuthReqToAppRedirect(authReq, targetWallet, metadata)
    redirectToAPP.query shouldContain "state=TEST"
    redirectToAPP.query shouldContain "code="

    // APP: parse authorization code
    val code = OIDCUtils.getCodeFromRedirectUri(redirectToAPP)
    code shouldNotBe null

    // APP: get access token
    val tokenHttpResponse = TokenRequest(metadata.tokenEndpointURI, ClientID(), AuthorizationCodeGrant(AuthorizationCode(code), APP_REDIRECT)).toHTTPRequest().apply {
      authorization = ClientSecretBasic(ClientID(CLIENT_ID), Secret(CLIENT_SECRET)).toHTTPAuthorizationHeader()
    }.send()
    val tokenResponse = OIDCTokenResponse.parse(tokenHttpResponse)

    tokenResponse.indicatesSuccess() shouldBe true
    tokenResponse.oidcTokens.idToken.jwtClaimsSet.subject shouldBe DID

    // APP: get userInfo
    val userInfoHttpResponse = UserInfoRequest(metadata.userInfoEndpointURI, tokenResponse.toSuccessResponse().tokens.accessToken).toHTTPRequest().send()
    userInfoHttpResponse.indicatesSuccess() shouldBe true

    val userInfoResponse = UserInfoResponse.parse(userInfoHttpResponse)
    userInfoResponse.toSuccessResponse().userInfo.subject.value shouldBe DID

    val verifiableId = VC.toCredential() as VerifiableId
    userInfoResponse.toSuccessResponse().userInfo.name shouldBe "${verifiableId.credentialSubject!!.firstName} ${verifiableId.credentialSubject!!.familyName}"
    userInfoResponse.toSuccessResponse().userInfo.givenName shouldBe verifiableId.credentialSubject!!.firstName
    userInfoResponse.toSuccessResponse().userInfo.familyName shouldBe verifiableId.credentialSubject!!.familyName
    userInfoResponse.toSuccessResponse().userInfo.birthdate shouldBe verifiableId.credentialSubject!!.dateOfBirth
    userInfoResponse.toSuccessResponse().userInfo.gender.value shouldBe verifiableId.credentialSubject!!.gender

  }

}
