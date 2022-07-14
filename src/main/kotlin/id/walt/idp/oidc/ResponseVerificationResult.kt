package id.walt.idp.oidc

import id.walt.idp.nfts.NftResponseVerificationResult
import id.walt.verifier.backend.SIOPResponseVerificationResult

class ResponseVerificationResult(val siopResponseVerificationResult: SIOPResponseVerificationResult?=null, val nftresponseVerificationResult: NftResponseVerificationResult?=null
) {

    val isValid
        get() = (siopResponseVerificationResult != null && siopResponseVerificationResult.isValid) || (nftresponseVerificationResult != null && nftresponseVerificationResult.isValid)
}