package id.walt.idp.nfts

import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.HttpCode
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT

object NFTController {

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
        /*val sessionId = ctx.queryParam("sessionId")
        val account = ctx.queryParam("account")*/
        val sessionId = ctx.formParam("sessionId") ?: throw  BadRequestResponse("Session not specified")
        val account = ctx.formParam("account") ?: throw  BadRequestResponse("Account not specified")

        val result = NFTManager.verifyNftOwnershipResponse(sessionId, account)
        val responseVerificationResult= ResponseVerificationResult(siopResponseVerificationResult = null,result)
        val uri= OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
        println(result.valid)
        //ctx.result("handle callback")
        ctx.status(HttpCode.FOUND).header("Location", uri.toString())

    }

}