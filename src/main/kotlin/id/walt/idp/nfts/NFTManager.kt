package id.walt.idp.nfts

import com.nimbusds.jose.shaded.json.JSONObject
import com.nimbusds.jose.shaded.json.parser.JSONParser
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.oidc.OIDCManager
import id.walt.nftkit.services.NftService
import id.walt.nftkit.services.VerificationService
import id.walt.vclib.model.VerifiableCredential.Companion.klaxon
import java.math.BigInteger

object  NFTManager  {

    fun verifyNftOwnershipResponse(sessionId: String, account: String) : NftResponseVerificationResult{
        val result= nftCollectionOwnershipVerification(sessionId, account)
        val nftResponseVerificationResult= NftResponseVerificationResult(account, sessionId, result)
        return nftResponseVerificationResult
    }

    fun getNFTClaims(authRequest: AuthorizationRequest): NFTClaims {
        val claims =
            (authRequest.requestObject?.jwtClaimsSet?.claims?.get("claims")?.toString()
                ?: authRequest.customParameters["claims"]?.firstOrNull())
                ?.let { JSONParser(-1).parse(it) as JSONObject }
                ?.let { when(it.containsKey("nftClaim") ) {
                    true -> it.toJSONString()
                    else -> it.get("id_token")?.toString() // EBSI WCT: vp_token is wrongly (?) contained inside id_token object
                }}
                ?.let { klaxon.parse<NFTClaims>(it) } ?: NFTClaims()
        return claims
    }

    fun generateNftClaim(authRequest: AuthorizationRequest): NFTClaims {
        return getNFTClaims(authRequest)
    }

    private fun nftCollectionOwnershipVerification(sessionId: String, account: String): Boolean {
        val session= OIDCManager.getOIDCSession(sessionId)
        val balance= NftService.balanceOf(session?.NFTClaim?.nftClaim?.chain!!,
            session.NFTClaim.nftClaim.smartContractAddress!!, account)
        return if (balance!!.compareTo(BigInteger("0")) == 1) true else false
    }

}
