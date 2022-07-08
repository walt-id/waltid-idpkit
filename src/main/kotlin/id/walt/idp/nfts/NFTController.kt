package id.walt.idp.nfts

import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.Context
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
        val sessionId = ctx.queryParam("sessionId")
        val account = ctx.queryParam("account")
        val result = NFTManager.nftOwnershipVerification(sessionId!!, account!!)
        val session= OIDCManager.getOIDCSession(sessionId)
        if( result == true){
            println("success")
        }else{
            println("failure")

        }
    }
}