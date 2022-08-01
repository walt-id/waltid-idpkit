package id.walt.idp.siwe

import id.walt.idp.nfts.NFTController
import id.walt.idp.nfts.NftResponseVerificationResult
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.OIDCSession
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.siwe.SiweRequest
import id.walt.siwe.Web3jSignatureVerifier
import id.walt.siwe.eip4361.Eip4361Message
import java.net.URI
import java.util.HashSet

object SiweManager {

    val nonceBlacklists = HashSet<String>()

    fun messageAndSignatureVerification(session: OIDCSession, message: String, signature: String): Boolean {
        var result= true
        val request= SiweRequest(message, signature)

        val eip4361msg = Eip4361Message.fromString(request.message)

        if (session?.siweSession?.nonce != eip4361msg.nonce) {
            result= false
            //println("Invalid nonce was set.")
        }
        if (nonceBlacklists.contains(eip4361msg.nonce)) {
            result= false
            //println("Nonce reused.")
        }

        val address = eip4361msg.address.lowercase()
        val msgSignature = request.signature
        val origMsg = eip4361msg.toString()

        val signatureVerification = Web3jSignatureVerifier.verifySignature(address, msgSignature, origMsg)
        if (!signatureVerification) {
            result= false
            //println("Invalid signature.")
        }
        nonceBlacklists.add(eip4361msg.nonce)
        return result
    }

    fun generateErrorResponseObject(sessionId: String, address: String, errorMessage: String): URI {
        val siweResponseVerificationResult = SiweResponseVerificationResult(address, sessionId, false, error = errorMessage)
        val responseVerificationResult= ResponseVerificationResult(siopResponseVerificationResult = null, null,
            siweResponseVerificationResult)
        val uri= OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
        return uri
    }
}