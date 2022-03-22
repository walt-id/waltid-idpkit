package id.walt.oidp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.model.oidc.VpTokenClaim
import id.walt.verifier.backend.WalletConfiguration

data class OIDCSession (
  val id: String,
  val authRequest: AuthorizationRequest,
  val vpTokenClaim: VpTokenClaim,
  val wallet: WalletConfiguration
    )
