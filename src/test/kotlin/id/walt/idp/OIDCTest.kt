package id.walt.idp

import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.UserInfoRequest
import com.nimbusds.openid.connect.sdk.UserInfoResponse
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.custodian.Custodian
import id.walt.idp.config.IDPConfig
import id.walt.idp.rest.IDPRestAPI
import id.walt.model.DidMethod
import id.walt.model.dif.InputDescriptor
import id.walt.model.dif.PresentationDefinition
import id.walt.model.dif.VpSchema
import id.walt.model.oidc.OIDCProvider
import id.walt.model.oidc.SIOPv2Request
import id.walt.model.oidc.VCClaims
import id.walt.model.oidc.VpTokenClaim
import id.walt.servicematrix.ServiceMatrix
import id.walt.services.did.DidService
import id.walt.services.oidc.OIDC4VPService
import id.walt.services.oidc.OIDCUtils
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.vclib.credentials.VerifiablePresentation
import id.walt.vclib.model.toCredential
import id.walt.vclib.templates.VcTemplateManager
import id.walt.verifier.backend.VerifierConfig
import id.walt.webwallet.backend.config.WalletConfig
import io.javalin.http.HttpCode
import io.kotest.assertions.json.shouldMatchJson
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockkObject
import java.net.URI

class OIDCTest: AnnotationSpec() {

  val OIDC_URI = URI.create("http://localhost:8080/api/oidc")
  lateinit var DID: String
  lateinit var VC: String
  val APP_REDIRECT = URI.create("http://app")

  @BeforeClass
  fun init() {
    ServiceMatrix("service-matrix.properties")
    mockkObject(IDPConfig)
    mockkObject(VerifierConfig)
    every { IDPConfig.config } returns IDPConfig(externalUrl = "http://localhost:8080", "")
    every { VerifierConfig.config } returns VerifierConfig("http://localhost:8080", "http://localhost:8080/api/siop")
    DID = DidService.create(DidMethod.key)
    VC = Signatory.getService().issue("VerifiableId", ProofConfig(DID, DID, proofType = ProofType.LD_PROOF))
    IDPRestAPI.start()
  }

  @Test
  fun testGetVpToken() {
    val targetWallet = VerifierConfig.config.wallets.values.first()
    // APP: get oidc discovery document
    val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }
    metadata.claims shouldContain "vp_token"

    // APP: init oidc session (par request)
    val parHTTPResponse = PushedAuthorizationRequest(metadata.pushedAuthorizationRequestEndpointURI, AuthorizationRequest.Builder(ResponseType.CODE, ClientID())
      .customParameter("claims", VCClaims(
      vp_token = VpTokenClaim(PresentationDefinition(
        listOf(
          InputDescriptor(schema = VpSchema(uri = VcTemplateManager.loadTemplate("VerifiableId").credentialSchema!!.id))
        )))
    ).toJSONString())
      .state(State("TEST"))
      .redirectionURI(APP_REDIRECT)
      .build()).toHTTPRequest().send()

    parHTTPResponse.statusCode shouldBe HttpCode.CREATED.status

    val parResponse = PushedAuthorizationResponse.parse(parHTTPResponse)

    // APP: redirect to authorization endpoint on IDP
    val authHttpResponse = AuthorizationRequest.Builder(parResponse.toSuccessResponse().requestURI, ClientID())
      .endpointURI(metadata.authorizationEndpointURI)
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
    vcClaims.vp_token!!.presentation_definition.input_descriptors.map { id -> id.schema.uri } shouldContain VcTemplateManager.loadTemplate("VerifiableId").credentialSchema!!.id

    // WALLET: fulfill SIOP request on IDP
    val siopReq = SIOPv2Request(
      redirect_uri = authReq.redirectionURI.toString(),
      response_mode = authReq.responseMode.value,
      nonce = authReq.customParameters["nonce"]!!.first(),
      claims = vcClaims,
      state = authReq.state.value
    )
    val vpSvc = OIDC4VPService(OIDCProvider("", ""))
    val presentation = Custodian.getService().createPresentation(listOf(VC), DID, challenge = siopReq.nonce, expirationDate = null).toCredential() as VerifiablePresentation
    val siopResponse = vpSvc.getSIOPResponseFor(siopReq, DID, listOf(presentation))

    // IDP: redirects to APP with authorization code
    val redirectToAPP = URI.create(vpSvc.postSIOPResponse(siopReq, siopResponse))
    redirectToAPP.query shouldContain "state=TEST"
    redirectToAPP.query shouldContain "code="

    // APP: parse authorization code
    val code = OIDCUtils.getCodeFromRedirectUri(redirectToAPP)
    code shouldNotBe null

    // APP: get access token
    val tokenHttpResponse = TokenRequest(metadata.tokenEndpointURI, ClientID(), AuthorizationCodeGrant(AuthorizationCode(code), APP_REDIRECT)).toHTTPRequest().send()
    val tokenResponse = TokenResponse.parse(tokenHttpResponse)

    tokenResponse.indicatesSuccess() shouldBe true

    // APP: get userInfo
    val userInfoHttpResponse = UserInfoRequest(metadata.userInfoEndpointURI, tokenResponse.toSuccessResponse().tokens.accessToken).toHTTPRequest().send()
    userInfoHttpResponse.indicatesSuccess() shouldBe true

    val userInfoResponse = UserInfoResponse.parse(userInfoHttpResponse)
    userInfoResponse.toSuccessResponse().userInfo.subject.value shouldBe DID

    val vp_token = userInfoResponse.toSuccessResponse().userInfo.getStringClaim("vp_token")
    vp_token shouldNotBe null
    vp_token shouldMatchJson presentation.encode()
  }
}
