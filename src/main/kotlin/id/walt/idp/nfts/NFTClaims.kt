package id.walt.idp.nfts

import com.beust.klaxon.Json
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest
import id.walt.model.oidc.klaxon
import id.walt.nftkit.services.Chain
import net.minidev.json.JSONObject
import net.minidev.json.parser.JSONParser

data class NFTClaim(
    @Json(serializeNull = false)
    val chain: Chain?,
    @Json(serializeNull = false)
    val smartContractAddress: String?,
    /*@Json(serializeNull = false) //@ListOrSingleVC
    val vp_token: List<NftService.>? = null,*/

)

class NFTClaims (
    @Json(serializeNull = false) val nftClaim: NFTClaim? = null,
) : OIDCClaimsRequest() {
    override fun toJSONObject(): JSONObject {
        val o = super.toJSONObject()
        if(nftClaim != null) {
            o.put("nftClaim", JSONParser(JSONParser.MODE_PERMISSIVE).parse(klaxon.toJsonString(nftClaim)))
        }
        return o
    }
}