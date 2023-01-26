package id.walt.idp.siop

import id.walt.idp.IDPFactory
import id.walt.idp.context.ContextFactory
import id.walt.idp.context.ContextId
import id.walt.multitenancy.TenantContext
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.VerifierConfig
import id.walt.verifier.backend.VerifierManager
import id.walt.verifier.backend.VerifierState
import io.javalin.http.BadRequestResponse
import java.net.URI

class SIOPManager : VerifierManager() {

    override fun getVerificationRedirectionUri(verificationResult: SIOPResponseVerificationResult, uiUrl: String?): URI {
        val siopState = SIOPState.decode(verificationResult.state) ?: throw BadRequestResponse("Invalid state")
        return IDPFactory.getIDP(siopState.idpType)
            .continueIDPSessionForSIOPResponse(siopState.idpSessionId, verificationResult)
        //println("Verification result: $verificationResult")
        //return IDPFactory.getIDP(IDPType.OIDC)
        //    .continueIDPSessionForSIOPResponse(verificationResult.state, verificationResult).also { println("Continue successful!") }
    }

    /*
    private fun addSessionToOidcManager(authRequest: AuthorizationRequest) {
        println("Adding request: ${authRequest.state}...")
        val authorizationMode = OIDCManager.getAuthorizationModeFor(authRequest)

        OIDCSession(
            id = UUID.randomUUID().toString(),
            authRequest = authRequest,
            authorizationMode = authorizationMode,
            presentationDefinition = when (authorizationMode) {
                OIDCManager.AuthorizationMode.SIOP -> OIDCManager.generatePresentationDefinition(authRequest)
                else -> null
            },
            nftTokenClaim = when (authorizationMode) {
                OIDCManager.AuthorizationMode.NFT -> OIDCManager.generateNftClaim(authRequest)
                else -> null
            },
            wallet = when (authorizationMode) {
                OIDCManager.AuthorizationMode.SIOP -> {
                    val walletId = authRequest.customParameters["walletId"]?.firstOrNull()
                        ?: VerifierConfig.config.wallets.values.map { wc -> wc.id }.firstOrNull()
                        ?: throw InternalServerErrorResponse("Known wallets not configured")
                    VerifierConfig.config.wallets[walletId]
                        ?: throw BadRequestResponse("No wallet configuration found for given walletId")
                }

                OIDCManager.AuthorizationMode.NFT -> NFTConfig.config.nftWallet
                OIDCManager.AuthorizationMode.SIWE -> NFTConfig.config.nftWallet
            },
            siweSession = when (authorizationMode) {
                OIDCManager.AuthorizationMode.NFT -> SiweSession(nonce = UUID.randomUUID().toString())
                OIDCManager.AuthorizationMode.SIWE -> SiweSession(nonce = UUID.randomUUID().toString())
                else -> null
            }
        ).also {
            println("Added session: ${it.authRequest.state}")
            //OIDCManager.sessionCache.put(it.id, it)
            OIDCManager.sessionCache.put(it.authRequest.state.value, it)
        }
    }

    override fun newRequestBySchemaUris(
        walletUrl: URI,
        schemaUris: Set<String>,
        state: String?,
        redirectCustomUrlQuery: String,
        responseMode: ResponseMode
    ): AuthorizationRequest {
        println("NEW SCHEMA URI REQUEST: $schemaUris")
        val newReq = super.newRequestBySchemaUris(walletUrl, schemaUris, state, redirectCustomUrlQuery, responseMode)
        addSessionToOidcManager(newReq)
        return newReq
    }

    override fun newRequestByVcTypes(
        walletUrl: URI,
        vcTypes: Set<String>,
        state: String?,
        redirectCustomUrlQuery: String,
        responseMode: ResponseMode
    ): AuthorizationRequest {
        println("NEW VC TYPE REQUEST: $vcTypes")
        val newReq = super.newRequestByVcTypes(walletUrl, vcTypes, state, redirectCustomUrlQuery, responseMode)
        addSessionToOidcManager(newReq)
        return newReq
    }

    override fun newRequest(
        walletUrl: URI,
        presentationDefinition: PresentationDefinition,
        state: String?,
        redirectCustomUrlQuery: String,
        responseMode: ResponseMode
    ): AuthorizationRequest {
        println("NEW REQUEST: $presentationDefinition")
        val newReq = super.newRequest(walletUrl, presentationDefinition, state, redirectCustomUrlQuery, responseMode)
        addSessionToOidcManager(newReq)
        return newReq
    }
     */
}
