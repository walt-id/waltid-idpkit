package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.idp.nfts.NftTokenClaim
import id.walt.model.dif.PresentationDefinition
import id.walt.siwe.configuration.SiweSession
import id.walt.verifier.backend.WalletConfiguration

data class OIDCSession(
    val id: String,
    val authRequest: AuthorizationRequest,
    val authorizationMode: OIDCManager.AuthorizationMode,
    val nonce: String,
    val presentationDefinition: PresentationDefinition? = null,

    val siweSession: SiweSession? = null,
    val nftTokenClaim: NftTokenClaim? = null,
    val wallet: WalletConfiguration,
    var verificationResult: ResponseVerificationResult? = null
)
