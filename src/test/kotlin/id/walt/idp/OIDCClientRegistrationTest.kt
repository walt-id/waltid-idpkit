package id.walt.idp

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.client.*
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCClientRegistry
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.rest.IDPRestAPI
import id.walt.model.DidMethod
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.context.ContextManager
import id.walt.services.did.DidService
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.verifier.backend.VerifierConfig
import id.walt.webwallet.backend.context.WalletContextManager
import io.javalin.core.util.RouteOverviewUtil.metaInfo
import io.javalin.http.HttpCode
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.equality.shouldBeEqualToComparingFields
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkObject
import org.apache.http.HttpStatus
import java.net.URI
import java.util.*

class OIDCClientRegistrationTest: OIDCTestBase() {

  val REDIRECT_URI = URI("https://myapp.com/redirect")
  val REDIRECT_URI_UPDATE = URI("https://myapp.com/update")
  val CLIENT_NAME = "My APP Name"

  override fun customInit() {

  }

  @Test
  fun testGoodClientRegistration() {
    val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }

    // CREATE
    val req = ClientRegistrationRequest(metadata.registrationEndpointURI, ClientMetadata().apply {
      redirectionURI = REDIRECT_URI
      name = CLIENT_NAME
      tokenEndpointAuthMethod = metadata.tokenEndpointAuthMethods.first()
      scope = metadata.scopes
    }, BearerAccessToken(OIDCManager.getClientRegistrationToken()))

    val resp = req.toHTTPRequest().send()

    resp.statusCode shouldBe HttpCode.CREATED.status

    val registrationResponse = ClientRegistrationResponse.parse(resp).toSuccessResponse()
    registrationResponse.isForNewClient shouldBe true
    registrationResponse.clientInformation.metadata.redirectionURI shouldBe REDIRECT_URI
    registrationResponse.clientInformation.metadata.name shouldBe CLIENT_NAME

    // UPDATE
    val updateReq = ClientUpdateRequest(
      registrationResponse.clientInformation.registrationURI,
      registrationResponse.clientInformation.id,
      registrationResponse.clientInformation.registrationAccessToken,
      ClientMetadata().apply {
        redirectionURI = REDIRECT_URI_UPDATE
        name = CLIENT_NAME
        tokenEndpointAuthMethod = metadata.tokenEndpointAuthMethods.first()
        scope = metadata.scopes
      },
      registrationResponse.clientInformation.secret
    )

    val updateResp = updateReq.toHTTPRequest().send()
    updateResp.statusCode shouldBe HttpCode.OK.status

    val updateResponse = ClientRegistrationResponse.parse(updateResp).toSuccessResponse()
    updateResponse.isForNewClient shouldBe false
    updateResponse.clientInformation.metadata.redirectionURI shouldBe REDIRECT_URI_UPDATE
    updateResponse.clientInformation.id shouldBe registrationResponse.clientInformation.id
    updateResponse.clientInformation.secret shouldBe registrationResponse.clientInformation.secret

    // GET

    val getReq = ClientReadRequest(registrationResponse.clientInformation.registrationURI, registrationResponse.clientInformation.registrationAccessToken)
    val getResp = getReq.toHTTPRequest().send()
    getResp.statusCode shouldBe HttpCode.OK.status

    val readResponse = ClientRegistrationResponse.parse(getResp).toSuccessResponse()
    readResponse.clientInformation.id shouldBe registrationResponse.clientInformation.id
    readResponse.clientInformation.metadata.redirectionURI shouldBe REDIRECT_URI_UPDATE

    // DELETE

    val delReq = ClientDeleteRequest(registrationResponse.clientInformation.registrationURI, registrationResponse.clientInformation.registrationAccessToken)
    val delResp = delReq.toHTTPRequest().send()
    delResp.statusCode shouldBe  HttpCode.NO_CONTENT.status

    val getReq2 = ClientReadRequest(registrationResponse.clientInformation.registrationURI, registrationResponse.clientInformation.registrationAccessToken)
    val getResp2 = getReq.toHTTPRequest().send()
    getResp2.statusCode shouldBe HttpCode.UNAUTHORIZED.status

  }
}
