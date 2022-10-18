package id.walt.idp.nfts

import id.walt.nftkit.services.NftMetadata

class NftResponseVerificationResult(
    val account: String,
    val sessionId: String,
    val valid: Boolean = false,
    val metadata: NftMetadata? = null,
    val error: String? = null
) {

    val isValid
        get() = valid

}
