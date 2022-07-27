package id.walt.idp.nfts

import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.idp.siwe.SiweManager
import id.walt.siwe.SiweRequest
import id.walt.siwe.Web3jSignatureVerifier
import id.walt.siwe.eip4361.Eip4361Message
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.HttpCode
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT
import java.util.HashSet

data class SiweSessionRequest(
    val message: String,
    val signature: String,
    val session: String
)
object NFTController {

    val nonceBlacklists = HashSet<String>()

    val routes
        get() = ApiBuilder.path("") {
            ApiBuilder.before(JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))

            ApiBuilder.post(
                "callback", documented(
                    document().operation {
                        it.summary("NFT callback endpoint")
                            .addTagsItem("OIDC-NFT")
                            .operationId("NFT callback")
                    },
                    NFTController::nftVerification
                ), OIDCAuthorizationRole.UNAUTHORIZED
            )
        }

    fun nftVerification(ctx: Context){

        val siweSessionRequest = ctx.bodyAsClass(SiweSessionRequest::class.java)

        if (siweSessionRequest == null) {
            val uri= NFTManager.generateErrorResponseObject(siweSessionRequest.session, "", "Invalid or no request was sent.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        val request= SiweRequest(siweSessionRequest.message, siweSessionRequest.signature)
        val session= OIDCManager.getOIDCSession(siweSessionRequest.session)
        val eip4361msg = Eip4361Message.fromString(request.message)

        if (session == null) {
            val uri= NFTManager.generateErrorResponseObject(siweSessionRequest.session, eip4361msg.address, "Invalid or no session was set.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }
        if (!session?.authorizationMode?.equals(OIDCManager.AuthorizationMode.NFT)!!) {
            val uri= NFTManager.generateErrorResponseObject(siweSessionRequest.session, eip4361msg.address, "Invalid callback.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if(!SiweManager.messageAndSignatureVerification(session, siweSessionRequest.message, siweSessionRequest.signature)){
            val uri= NFTManager.generateErrorResponseObject(siweSessionRequest.session, eip4361msg.address, "Invalid signature.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        val result = NFTManager.verifyNftOwnershipResponse(siweSessionRequest.session, eip4361msg.address)
        val responseVerificationResult= ResponseVerificationResult(siopResponseVerificationResult = null,result)
        val uri= OIDCManager.continueIDPSessionResponse(siweSessionRequest.session, responseVerificationResult)
        ctx.status(HttpCode.FOUND).header("Location", uri.toString())

    }


}