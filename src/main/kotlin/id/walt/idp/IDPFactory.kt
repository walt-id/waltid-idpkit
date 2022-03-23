package id.walt.idp

import id.walt.idp.oidc.OIDCManager
import id.walt.idp.siop.SIOPState

object IDPFactory {

  fun getIDP(idpType: IDPType): IDPManager {
    when(idpType) {
      IDPType.OIDC -> return OIDCManager
    }
  }
}
