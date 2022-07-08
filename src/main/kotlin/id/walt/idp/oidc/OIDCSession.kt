package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.nfts.NFTClaims
import id.walt.model.oidc.VpTokenClaim
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.WalletConfiguration

data class OIDCSession (
  val id: String,
  val authRequest: AuthorizationRequest,
  val vpTokenClaim: VpTokenClaim?= null,
  val NFTClaim: NFTClaims?= null,
  val wallet: WalletConfiguration,
  var verificationResult: SIOPResponseVerificationResult? = null
    )
