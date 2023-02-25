package id.walt.idp.nfts

import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.idp.siwe.SiweManager
import id.walt.idp.siwe.SiwnManager
import id.walt.idp.siwe.SiwtManager
import id.walt.siwe.SiweRequest
import id.walt.siwe.eip4361.Eip4361Message
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.HttpCode
import io.javalin.plugin.openapi.dsl.document
import io.javalin.plugin.openapi.dsl.documented
import javalinjwt.JavalinJWT


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

    fun nftVerification(ctx: Context) {

        val sessionId = ctx.queryParam("session") ?: throw BadRequestResponse("Session not specified")
        val message = ctx.queryParam("message") ?: throw BadRequestResponse("Message not specified")
        val signature = ctx.queryParam("signature") ?: throw BadRequestResponse("Signature not specified")
        val chain = ctx.queryParam("chain") ?: throw BadRequestResponse("Chain not specified")


        val session = OIDCManager.getOIDCSession(sessionId)
        if (session == null) {
            val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid or no session was set.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if (!OIDCManager.AuthorizationMode.NFT.equals(session?.authorizationMode)) {
            val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid callback.")
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if ("EVM".equals(chain)){
            val request = SiweRequest(message, signature)
            val eip4361msg = Eip4361Message.fromString(request.message)

            if (!SiweManager.messageAndSignatureVerification(session!!, message, signature)) {
                val uri = NFTManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid signature.")
                ctx.status(HttpCode.FOUND).header("Location", uri.toString())
            } else {
                val result = NFTManager.verifyNftOwnershipResponse(sessionId, eip4361msg.address)
                if (IDPConfig.config.claimConfig?.default_nft_policy == null) {
                    throw BadRequestResponse("Missed policy configuration")
                }
                if (result.isValid && IDPConfig.config.claimConfig?.default_nft_policy!!.withPolicyVerification!!) {
                    val policyVerification = NFTManager.verifyNftMetadataAgainstPolicy(result.metadata!!)
                    if (policyVerification) {
                        val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
                        val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    } else {
                        val uri = NFTManager.generateErrorResponseObject(sessionId, eip4361msg.address, "Invalid policy verification.")
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    }
                } else {
                    val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
                    val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                    ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                }
            }
        }else if("Tezos".equals(chain)){
            val publicKey= SiwtManager.getPublicKey(message)
            val address= SiwtManager.getAddress(message)
            if(!SiwtManager.verifySignature(session!!,message, publicKey, signature)){
                val uri = NFTManager.generateErrorResponseObject(sessionId, address, "Invalid signature.")
                ctx.status(HttpCode.FOUND).header("Location", uri.toString())
            }else{
                val result = NFTManager.verifyTezosNftOwnership(sessionId, address)
                if(result.isValid && IDPConfig.config.claimConfig?.default_nft_policy!!.withPolicyVerification!!){
                    val policyVerification = NFTManager.verifyNftMetadataAgainstPolicy(result.metadata!!)
                    if (policyVerification) {
                        val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
                        val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    } else {
                        val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid policy verification.")
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    }
                }else{
                    val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
                    val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                    ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                }

            }
        }
        else if("TESTNET".equals(chain)){
            val publicKey = SiwnManager.getPublicKey(message)
            print(publicKey)
            val address = SiwnManager.getAddress(message)
            print(address)

            if (!SiwnManager.verifySignature(session!!, message, publicKey, signature)) {
                val uri = NFTManager.generateErrorResponseObject(sessionId, address, "Invalid signature.")
                ctx.status(HttpCode.FOUND).header("Location", uri.toString())
            }
            else{
                val result = NFTManager.verifyNearNftOwnership(sessionId, address)
                if (result.isValid && IDPConfig.config.claimConfig?.default_nft_policy!!.withPolicyVerification!!){
                    val policyVerification = NFTManager.verifyNftMetadataAgainstPolicy(result.metadata!!)
                    if (policyVerification) {
                        val responseVerificationResult =
                            ResponseVerificationResult(siopResponseVerificationResult = null, result)
                        val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    } else {
                        val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid policy verification.")
                        ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                    }
                }else{
                    val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
                    val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
                    ctx.status(HttpCode.FOUND).header("Location", uri.toString())
                }
            }
        }

    }


}
