package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.nfts.NFTClaim
import id.walt.model.oidc.VpTokenClaim
import id.walt.verifier.backend.WalletConfiguration
import id.walt.siwe.configuration.SiweSession
data class OIDCSession (
  val id: String,
  val authRequest: AuthorizationRequest,
  val authorizationMode: OIDCManager.AuthorizationMode,
  val vpTokenClaim: VpTokenClaim?= null,

  val siweSession:SiweSession?=null,
  val nftClaim: NFTClaim?= null,
  val wallet: WalletConfiguration,
  var verificationResult: ResponseVerificationResult? = null
    )
