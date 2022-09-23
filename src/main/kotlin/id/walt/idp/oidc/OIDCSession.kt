package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.nfts.NftTokenClaim
import id.walt.model.dif.PresentationDefinition
import id.walt.model.oidc.VpTokenClaim
import id.walt.verifier.backend.WalletConfiguration
import id.walt.siwe.configuration.SiweSession
data class OIDCSession (
  val id: String,
  val authRequest: AuthorizationRequest,
  val authorizationMode: OIDCManager.AuthorizationMode,
  val presentationDefinition: PresentationDefinition? = null,

  val siweSession:SiweSession?=null,
  val nftTokenClaim: NftTokenClaim?= null,
  val wallet: WalletConfiguration,
  var verificationResult: ResponseVerificationResult? = null
    )
