package id.walt.idp.siwe

import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.siwe.SiweRequest
import id.walt.siwe.eip4361.Eip4361Message
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.HttpCode
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT

object SIWEController {

    val routes
        get() = ApiBuilder.path("") {
            ApiBuilder.before(JavalinJWT.createHeaderDecodeHandler(OIDCManager.accessTokenProvider))

            ApiBuilder.get(
                "callback", documented(
                    document().operation {
                        it.summary("SIWE callback endpoint")
                            .addTagsItem("OIDC-SIWE")
                            .operationId("SIWE callback")
                    },
                    SIWEController::siweVerification
                ), OIDCAuthorizationRole.UNAUTHORIZED
            )
        }

    fun siweVerification(ctx: Context) {

        val sessionId = ctx.queryParam("session") ?: throw BadRequestResponse("Session not specified")
        val message = ctx.queryParam("message") ?: throw BadRequestResponse("Message not specified")
        val signature = ctx.queryParam("signature") ?: throw BadRequestResponse("Signature not specified")

        val request = SiweRequest(message, signature)
        val session = OIDCManager.getOIDCSession(sessionId)
        val eip4361msg = Eip4361Message.fromString(request.message)

        if (session == null) {
            val uri = SiweManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid or no session was set.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if (!OIDCManager.AuthorizationMode.SIWE.equals(session?.authorizationMode)) {
            val uri = SiweManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid callback.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }


        if (SiweManager.messageAndSignatureVerification(session!!, message, signature)) {
            val siweResponseVerificationResult = SiweResponseVerificationResult(eip4361msg.address, sessionId, true)
            val responseVerificationResult = ResponseVerificationResult(null, null, siweResponseVerificationResult)
            val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        } else {
            val uri = SiweManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid signature.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

    }
}
