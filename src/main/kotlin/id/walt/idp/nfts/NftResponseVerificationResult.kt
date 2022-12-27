package id.walt.idp.nfts

import id.walt.nftkit.services.NftMetadata
import id.walt.nftkit.services.NftMetadataWrapper

class NftResponseVerificationResult(
    val account: String,
    val sessionId: String,
    val valid: Boolean = false,
    val metadata: NftMetadataWrapper? = null,
    val error: String? = null
) {

    val isValid
        get() = valid

}
