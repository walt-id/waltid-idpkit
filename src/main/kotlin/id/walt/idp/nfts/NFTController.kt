package id.walt.idp.nfts

import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.idp.siwe.SiweManager
import id.walt.idp.siwe.SiweResponseVerificationResult
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
import java.net.URI
import java.util.HashSet


object NFTController {

    val nonceBlacklists = HashSet<String>()

    val routes
        get() = ApiBuilder.path("") {
            ApiBuilder.before(JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))

            ApiBuilder.get(
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

        val sessionId = ctx.queryParam("session") ?: throw  BadRequestResponse("Session not specified")
        val message = ctx.queryParam("message") ?: throw  BadRequestResponse("Message not specified")
        val signature = ctx.queryParam("signature") ?: throw  BadRequestResponse("Signature not specified")

        val request= SiweRequest(message, signature)
        val session= OIDCManager.getOIDCSession(sessionId)
        val eip4361msg = Eip4361Message.fromString(request.message)

        if (session == null) {
            val uri= NFTManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid or no session was set.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }
        if (!OIDCManager.AuthorizationMode.NFT.equals(session?.authorizationMode) ) {
            val uri= NFTManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid callback.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if(!SiweManager.messageAndSignatureVerification(session!!, message, signature)){
            val uri= NFTManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid signature.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        val result = NFTManager.verifyNftOwnershipResponse(sessionId, eip4361msg.address)
        val responseVerificationResult= ResponseVerificationResult(siopResponseVerificationResult = null,result)
        val uri= OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
        ctx.status(HttpCode.FOUND).header("Location", uri.toString())

    }


}