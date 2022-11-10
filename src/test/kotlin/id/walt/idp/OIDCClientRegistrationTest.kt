package id.walt.idp

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.client.*
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.idp.oidc.OIDCManager
import io.javalin.http.HttpCode
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import java.net.URI

class OIDCClientRegistrationTest : OIDCTestBase() {

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

        val getReq = ClientReadRequest(
            registrationResponse.clientInformation.registrationURI,
            registrationResponse.clientInformation.registrationAccessToken
        )
        val getResp = getReq.toHTTPRequest().send()
        getResp.statusCode shouldBe HttpCode.OK.status

        val readResponse = ClientRegistrationResponse.parse(getResp).toSuccessResponse()
        readResponse.clientInformation.id shouldBe registrationResponse.clientInformation.id
        readResponse.clientInformation.metadata.redirectionURI shouldBe REDIRECT_URI_UPDATE

        // DELETE

        val delReq = ClientDeleteRequest(
            registrationResponse.clientInformation.registrationURI,
            registrationResponse.clientInformation.registrationAccessToken
        )
        val delResp = delReq.toHTTPRequest().send()
        delResp.statusCode shouldBe HttpCode.NO_CONTENT.status

        val getReq2 = ClientReadRequest(
            registrationResponse.clientInformation.registrationURI,
            registrationResponse.clientInformation.registrationAccessToken
        )
        val getResp2 = getReq2.toHTTPRequest().send()
        getResp2.statusCode shouldBe HttpCode.UNAUTHORIZED.status

    }

    @Test
    fun testIncompatibleClientRegistration() {
        val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }

        // CREATE
        val req = ClientRegistrationRequest(metadata.registrationEndpointURI, ClientMetadata().apply {
            redirectionURI = REDIRECT_URI
            name = CLIENT_NAME
            // client_secret_jwt auth currently not supported by IDP Kit
            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT
            scope = metadata.scopes
        }, BearerAccessToken(OIDCManager.getClientRegistrationToken()))

        val resp = req.toHTTPRequest().send()

        resp.statusCode shouldBe HttpCode.BAD_REQUEST.status
        ClientRegistrationResponse.parse(resp).toErrorResponse().errorObject shouldBe RegistrationError.INVALID_CLIENT_METADATA
    }

    @Test
    fun testGetOtherClient() {
        val metadata = shouldNotThrowAny { OIDCProviderMetadata.resolve(Issuer(OIDC_URI)) }

        // CREATE Client 1
        val req1 = ClientRegistrationRequest(metadata.registrationEndpointURI, ClientMetadata().apply {
            redirectionURI = REDIRECT_URI
            name = CLIENT_NAME
            tokenEndpointAuthMethod = metadata.tokenEndpointAuthMethods.first()
            scope = metadata.scopes
        }, BearerAccessToken(OIDCManager.getClientRegistrationToken()))
        val resp1 = req1.toHTTPRequest().send()
        resp1.statusCode shouldBe HttpCode.CREATED.status
        val registrationResponse1 = ClientRegistrationResponse.parse(resp1).toSuccessResponse()

        // CREATE Client 2
        val req2 = ClientRegistrationRequest(metadata.registrationEndpointURI, ClientMetadata().apply {
            redirectionURI = REDIRECT_URI
            name = CLIENT_NAME
            tokenEndpointAuthMethod = metadata.tokenEndpointAuthMethods.first()
            scope = metadata.scopes
        }, BearerAccessToken(OIDCManager.getClientRegistrationToken()))
        val resp2 = req2.toHTTPRequest().send()
        resp2.statusCode shouldBe HttpCode.CREATED.status
        val registrationResponse2 = ClientRegistrationResponse.parse(resp2).toSuccessResponse()

        // GET // try to get client 2 info with client 1 access token

        val getReq = ClientReadRequest(
            registrationResponse2.clientInformation.registrationURI,
            registrationResponse1.clientInformation.registrationAccessToken
        )
        val getResp = getReq.toHTTPRequest().send()
        getResp.statusCode shouldBe HttpCode.FORBIDDEN.status
    }

    @Test
    fun testGetNonExistingClient() {
        // GET // try to get non-existing client info with client 1 access token
        val clientId = "xyz"
        val token = OIDCManager.getClientRegistrationToken(clientId)
        val getReq2 = ClientReadRequest(URI("$OIDC_URI/clients/xyz"), BearerAccessToken(token))
        val getResp2 = getReq2.toHTTPRequest().send()
        getResp2.statusCode shouldBe HttpCode.UNAUTHORIZED.status
    }
}
