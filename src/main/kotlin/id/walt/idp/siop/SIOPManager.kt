package id.walt.idp.siop

import id.walt.idp.IDPFactory
import id.walt.services.hkvstore.FileSystemHKVStore
import id.walt.services.hkvstore.FilesystemStoreConfig
import id.walt.services.keystore.HKVKeyStoreService
import id.walt.services.vcstore.HKVVcStoreService
import id.walt.verifier.backend.SIOPResponseVerificationResult
import id.walt.verifier.backend.VerifierManager
import id.walt.webwallet.backend.context.UserContext
import io.javalin.http.BadRequestResponse
import java.net.URI

class SIOPManager: VerifierManager() {

  override val verifierContext = UserContext(
    contextId = "SIOPManager",
    hkvStore = FileSystemHKVStore(FilesystemStoreConfig("${id.walt.WALTID_DATA_ROOT}/data/verifier")),
    keyStore = HKVKeyStoreService(),
    vcStore = HKVVcStoreService()
  )

  override fun getVerificationRedirectionUri(verificationResult: SIOPResponseVerificationResult, uiUrl: String?): URI {
    val siopState = SIOPState.decode(verificationResult.state) ?: throw BadRequestResponse("Invalid state")
    return IDPFactory.getIDP(siopState.idpType).continueIDPSessionForSIOPResponse(siopState.idpSessionId, verificationResult)
  }
}
