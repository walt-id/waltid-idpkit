package id.walt.idp.nfts

import com.nimbusds.jose.shaded.json.JSONObject
import com.nimbusds.jose.shaded.json.parser.JSONParser
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCManager
import id.walt.nftkit.services.NftService
import id.walt.nftkit.services.VerificationService
import id.walt.vclib.model.VerifiableCredential.Companion.klaxon
import java.math.BigInteger

object  NFTManager  {

    private const val NFT_API_PATH: String = "api/nft"
    val NFTApiUrl: String get() = "${IDPConfig.config.externalUrl}/$NFT_API_PATH"

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
                    else -> it.get("id_token")?.toString()
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
        return balance!!.compareTo(BigInteger("0")) == 1
    }

}
