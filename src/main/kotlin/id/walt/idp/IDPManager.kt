package id.walt.idp

import id.walt.verifier.backend.SIOPResponseVerificationResult
import java.net.URI

interface IDPManager {

  /**
   * Continue IDP session for SIOP response verification result
   * @return User agent redirection URI
   */
  fun continueIDPSessionForSIOPResponse(sessionId: String, verificationResult: SIOPResponseVerificationResult): URI

  val idpType: IDPType
}
