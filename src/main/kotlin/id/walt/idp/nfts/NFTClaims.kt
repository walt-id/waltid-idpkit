package id.walt.idp.nfts

import com.beust.klaxon.Json
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest
import id.walt.common.KlaxonWithConverters
import id.walt.nftkit.services.Chain
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser

data class NftTokenConstraint(
    @Json(serializeNull = false)
    val chain: Chain?,
    @Json(serializeNull = false)
    val smartContractAddress: String?,
    @Json(serializeNull = false)
    val factorySmartContractAddress: String?,
)

enum class ChainEcosystem {
    EVM, TEZOS, NEAR , POLKADOT, FLOW
}

data class NftTokenClaim(
    val ecosystems: Set<ChainEcosystem>,
    val nftTokenContraints: Map<String, NftTokenConstraint>
)

class NFTClaims(
    @Json(serializeNull = false) val nft_token: NftTokenClaim? = null,
) : OIDCClaimsRequest() {
    override fun toJSONObject(): JSONObject {
        val o = super.toJSONObject()
        if (nft_token != null) {
            o["nft_token"] = JSONParser(JSONParser.MODE_PERMISSIVE).parse(KlaxonWithConverters().toJsonString(nft_token))
        }
        return o
    }
}
