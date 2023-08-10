package id.walt.idp.nfts

import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCAuthorizationRole
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.idp.siwe.*
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
      print("Session ID: $sessionId")
        val message = ctx.queryParam("message") ?: throw BadRequestResponse("Message not specified")
      print("Message: $message")
        val ecosystem = ctx.queryParam("ecosystem")?.let { ChainEcosystem.valueOf(it.uppercase()) } ?: throw BadRequestResponse("Ecosystem not specified")
      print("Ecosystem: $ecosystem")
        val signature = ctx.queryParam("signature") ?: throw BadRequestResponse("Signature not specified")
      print("Signature: $signature")


        val session = OIDCManager.getOIDCSession(sessionId)
        if (session == null) {
            val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid or no session was set.", ecosystem)
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        if (!OIDCManager.AuthorizationMode.NFT.equals(session?.authorizationMode)) {
            val uri = NFTManager.generateErrorResponseObject(sessionId, "", "Invalid callback.", ecosystem)
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        }

        var address = ""
        val siwxResult = when(ecosystem) {
          ChainEcosystem.EVM -> {
            val request = SiweRequest(message, signature)
            address = Eip4361Message.fromString(request.message).address
            SiweManager.messageAndSignatureVerification(session!!, message, signature)
          }
          ChainEcosystem.TEZOS -> {
            val publicKey = SiwtManager.getPublicKey(message)
            address = SiwtManager.getAddress(message)
            SiwtManager.verifySignature(session!!,message, publicKey, signature)
          }
          ChainEcosystem.NEAR -> {
            val publicKey = SiwnManager.getPublicKey(message)
            print("Public Key: $publicKey")
            address = SiwnManager.getAddress(message)
            print("Address: $address")
            SiwnManager.verifySignature(session!!, message, publicKey, signature)
          }
          ChainEcosystem.POLKADOT -> {
            val publicKey = SiwpManager.getPublicKey(message)
            address = SiwpManager.getPublicKey(message)


            SiwpManager.verifySignature(session!!, message, publicKey, signature)
          }

          ChainEcosystem.FLOW -> {

            address = siwfManager.getAddress(message)
            siwfManager.verifySignature(session!!, message, signature)

          }

          ChainEcosystem.ALGORAND -> {
            address = siwaManager.getAddress(message)
            val publicKey = siwaManager.getPublicKey(message)
            siwaManager.verifySignature(session!!, message, publicKey,signature)
          }

        }

        if(!siwxResult) {
          val uri = NFTManager.generateErrorResponseObject(sessionId, address, "Invalid signature.", ecosystem)
          ctx.status(HttpCode.FOUND).header("Location", uri.toString())
        } else {
          val result = NFTManager.verifyNftOwnershipResponse(sessionId, address, ecosystem)
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
              val uri = NFTManager.generateErrorResponseObject(sessionId, address, "Invalid policy verification.", ecosystem)
              ctx.status(HttpCode.FOUND).header("Location", uri.toString())
            }
          } else {
            val responseVerificationResult = ResponseVerificationResult(siopResponseVerificationResult = null, result)
            val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
            ctx.status(HttpCode.FOUND).header("Location", uri.toString())
          }
        }
    }


}
