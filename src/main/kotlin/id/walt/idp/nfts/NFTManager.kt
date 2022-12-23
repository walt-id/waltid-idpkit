package id.walt.idp.nfts

import com.nimbusds.jose.shaded.json.JSONObject
import com.nimbusds.jose.shaded.json.parser.JSONParser
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.common.klaxonWithConverters
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.nftkit.opa.DynamicPolicy
import id.walt.nftkit.services.*
import java.math.BigInteger
import java.net.URI
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object NFTManager {

    private const val NFT_API_PATH: String = "api/nft"
    val NFTApiUrl: String get() = "${IDPConfig.config.externalUrl}/$NFT_API_PATH"

    fun verifyNftOwnershipResponse(sessionId: String, account: String): NftResponseVerificationResult {
        val result = nftCollectionOwnershipVerification(sessionId, account)
        val error = if (result) null else "Invalid Ownership"
        var nft: NftMetadata? = null

        if (result) {
            nft = getAccountNftMetadata(sessionId, account)
        }
        val nftResponseVerificationResult = NftResponseVerificationResult(account, sessionId, result, nft, error = error)
        return nftResponseVerificationResult
    }

    fun verifyTezosNftOwnership(sessionId: String, account: String): NftResponseVerificationResult {
        val result= tezosNftCollectionOwnershipVerification(sessionId, account)
        val error = if (result) null else "Invalid Ownership"
        var nft: NftMetadata? = null

        if (result) {
            //nft = getAccountNftMetadata(sessionId, account)
        }
        val nftResponseVerificationResult = NftResponseVerificationResult(account, sessionId, result, nft, error = error)
        return nftResponseVerificationResult
    }

    fun getNFTClaims(authRequest: AuthorizationRequest): NFTClaims {
        val claims =
            (authRequest.requestObject?.jwtClaimsSet?.claims?.get("claims")?.toString()
                ?: authRequest.customParameters["claims"]?.firstOrNull())
                ?.let { JSONParser(-1).parse(it) as JSONObject }
                ?.let {
                    when (it.containsKey("nft_token")) {
                        true -> it.toJSONString()
                        else -> null
                    }
                }
                ?.let { klaxonWithConverters.parse<NFTClaims>(it) } ?: NFTClaims()
        return claims
    }

    fun generateNftClaim(authRequest: AuthorizationRequest): NFTClaims {
        return getNFTClaims(authRequest)
    }

    fun generateErrorResponseObject(sessionId: String, address: String, errorMessage: String): URI {
        val nftResponseVerificationResult = NftResponseVerificationResult(address, sessionId, false, error = errorMessage)
        val responseVerificationResult = ResponseVerificationResult(null, nftResponseVerificationResult, null)
        val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
        return uri
    }

    fun verifyNftMetadataAgainstPolicy(nftMetadata: NftMetadata): Boolean {
        return DynamicPolicy.doVerify(
            IDPConfig.config.claimConfig?.default_nft_policy!!.inputs,
            IDPConfig.config.claimConfig?.default_nft_policy!!.policy,
            IDPConfig.config.claimConfig?.default_nft_policy!!.query,
            nftMetadata
        )
    }

    private fun nftCollectionOwnershipVerification(sessionId: String, account: String): Boolean {
        val session = OIDCManager.getOIDCSession(sessionId)
        if(session?.nftTokenClaim?.factorySmartContractAddress.equals("") || session?.nftTokenClaim?.factorySmartContractAddress == null ) {
            val balance = NftService.balanceOf(
                session?.nftTokenClaim?.chain!!,
                session.nftTokenClaim.smartContractAddress!!, account.trim()
            )
            return balance!!.compareTo(BigInteger("0")) == 1
        }else{
            println("data nft verification")
            return VerificationService.dataNftVerification(session?.nftTokenClaim?.chain!!, session?.nftTokenClaim?.factorySmartContractAddress!!,
                    session?.nftTokenClaim?.smartContractAddress!!, account.trim(), "", null)
        }
    }

    private fun tezosNftCollectionOwnershipVerification(sessionId: String, account: String): Boolean {
        val session = OIDCManager.getOIDCSession(sessionId)
        val result = VerificationService.verifyNftOwnershipWithinCollection(session?.nftTokenClaim?.chain!!,
            session?.nftTokenClaim?.smartContractAddress!!,account)
            return result

    }

    private fun getAccountNftMetadata(sessionId: String, account: String): NftMetadata {
        val session = OIDCManager.getOIDCSession(sessionId)
        val nfts = NftService.getAccountNFTsByAlchemy(session?.nftTokenClaim?.chain!!, account)
            .filter { it.contract.address.equals(session.nftTokenClaim.smartContractAddress, ignoreCase = true) }
            .sortedBy { it.id.tokenId }
        return nfts.get(0).metadata!!
    }

}
