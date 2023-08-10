package id.walt.idp.nfts

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.common.KlaxonWithConverters
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.oidc.ResponseVerificationResult
import id.walt.nftkit.opa.DynamicPolicy
import id.walt.nftkit.services.*
import id.walt.nftkit.utilis.Common
import mu.KotlinLogging
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser
import java.math.BigInteger
import java.net.URI

object NFTManager {

    private const val NFT_API_PATH: String = "api/nft"
    val NFTApiUrl: String get() = "${IDPConfig.config.externalUrl}/$NFT_API_PATH"
    val logger = KotlinLogging.logger {  }

    fun verifyNftOwnershipResponse(sessionId: String, account: String, ecosystem: ChainEcosystem): NftResponseVerificationResult {
        val result = nftCollectionOwnershipVerification(sessionId, account, ecosystem)
        val error = if (result) null else "Invalid Ownership"
        var nft: NftMetadataWrapper? = null

        if (result) {
            nft = getAccountNftMetadata(sessionId, account, ecosystem)
        }

        val nftResponseVerificationResult = NftResponseVerificationResult(ecosystem, account, sessionId, result, nft, error = error)
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
                ?.let { KlaxonWithConverters().parse<NFTClaims>(it) } ?: NFTClaims()
        return claims
    }

    fun generateNftClaim(authRequest: AuthorizationRequest): NFTClaims {
        return getNFTClaims(authRequest)
    }

    fun generateErrorResponseObject(sessionId: String, address: String, errorMessage: String, ecosystem: ChainEcosystem): URI {
        val nftResponseVerificationResult = NftResponseVerificationResult(ecosystem, address, sessionId, false, error = errorMessage)
        val responseVerificationResult = ResponseVerificationResult(null, nftResponseVerificationResult, null)
        val uri = OIDCManager.continueIDPSessionResponse(sessionId, responseVerificationResult)
        return uri
    }

    fun verifyNftMetadataAgainstPolicy(nftMetadata: NftMetadataWrapper): Boolean {
        return DynamicPolicy.doVerify(
            IDPConfig.config.claimConfig?.default_nft_policy!!.inputs,
            IDPConfig.config.claimConfig?.default_nft_policy!!.policy,
            IDPConfig.config.claimConfig?.default_nft_policy!!.query,
            nftMetadata
        )
    }

    private fun nftCollectionOwnershipVerification(sessionId: String, account: String, ecosystem: ChainEcosystem): Boolean {
        val session = OIDCManager.getOIDCSession(sessionId) ?: return false.also { logger.error { "Session not found" } }
        val tokenConstraint = session.nftTokenClaim?.nftTokenContraints?.get(ecosystem.name)
          ?: return false.also { logger.error { "No nft token constraint found for given ecosystem" } }
        return if(tokenConstraint.factorySmartContractAddress.isNullOrEmpty()) {
          logger.info { "Verifying collection ownership on $ecosystem, for account: $account, chain: ${tokenConstraint.chain}, contract: ${tokenConstraint.smartContractAddress}" }
          when(ecosystem) {
            ChainEcosystem.EVM -> NftService.balanceOf(
                Common.getEVMChain(tokenConstraint.chain!!.toString()),
                tokenConstraint.smartContractAddress!!, account.trim()
              )?.compareTo(BigInteger("0")) == 1
            ChainEcosystem.TEZOS, ChainEcosystem.NEAR  , ChainEcosystem.POLKADOT-> VerificationService.verifyNftOwnershipWithinCollection(
              tokenConstraint.chain!!,
              tokenConstraint.smartContractAddress!!,account)

            ChainEcosystem.FLOW -> VerificationService.verifyNftOwnershipInCollectionFlow(tokenConstraint.chain!!,
              tokenConstraint.smartContractAddress!!,account ,tokenConstraint.collectionPath!!)

            ChainEcosystem.ALGORAND -> VerificationService.NFTsAlgorandOwnershipVerification(AlgorandChain.valueOf(
              tokenConstraint.chain!!.toString()
            ),tokenConstraint.smartContractAddress!!,account)
          }
        } else {
          println("data nft verification")
          when(ecosystem) {
            ChainEcosystem.EVM -> VerificationService.dataNftVerification(
              Common.getEVMChain(tokenConstraint.chain!!.toString()),
              tokenConstraint.factorySmartContractAddress!!,
              tokenConstraint.smartContractAddress!!, account.trim(), "", null
            )
            else -> false.also {
              logger.error { "Data NFT verification not supported for $ecosystem ecosystem" }
            }
          }
        }
    }

    private fun getAccountNftMetadata(sessionId: String, account: String, ecosystem: ChainEcosystem): NftMetadataWrapper {
        val session = OIDCManager.getOIDCSession(sessionId) ?: return NftMetadataWrapper().also { logger.error { "Session not found" } }
        val tokenConstraint = session.nftTokenClaim?.nftTokenContraints?.get(ecosystem.name)
          ?: return NftMetadataWrapper().also { logger.error { "No nft token constraint found for given ecosystem" } }
        return NftMetadataWrapper(
          evmNftMetadata = if(ecosystem == ChainEcosystem.EVM)
            NftService.getAccountNFTsByAlchemy(tokenConstraint.chain!!, account)
              .filter { it.contract.address.equals(tokenConstraint.smartContractAddress, ignoreCase = true) }
              .sortedBy { it.id.tokenId }.get(0).metadata!!
            else null,
          tezosNftMetadata = if(ecosystem == ChainEcosystem.TEZOS)
            TezosNftService.fetchAccountNFTsByTzkt(tokenConstraint.chain!!, account, tokenConstraint.smartContractAddress)
              .sortedBy { it.id }.get(0).token.metadata
            else null,
          nearNftMetadata = if(ecosystem == ChainEcosystem.NEAR)
            tokenConstraint.smartContractAddress?.let {
              NearNftService.getNFTforAccount( account, it, NearChain.valueOf(
                tokenConstraint.chain!!.toString()
              ))}?.get(0)
            else null,
          flowNftMetadata = if(ecosystem == ChainEcosystem.FLOW)
           FlowNftService.getAllNFTs(account , FlowChain.valueOf(tokenConstraint.chain!!.toString()) ).get(0)

            else null
        )
    }

  public fun getNearNftAttributeValue(metadata: NearTokenMetadata, key: String): String? = when(key) {
    "copies" -> metadata.copies?.toString()
    "description" -> metadata.description
    "expires_at" -> metadata.expires_at
    "extra" -> metadata.extra
    "issued_at" -> metadata.issued_at
    "media" -> metadata.media
    "media_hash" -> metadata.media_hash
    "reference" -> metadata.reference
    "reference_hash" -> metadata.reference_hash
    "starts_at" -> metadata.starts_at
    "title" -> metadata.title
    "updated_at" -> metadata.updated_at
    else -> null
  }
}
