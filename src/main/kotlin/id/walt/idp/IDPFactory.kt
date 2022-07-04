package id.walt.idp

import id.walt.idp.oidc.OIDCManager

object IDPFactory {

  fun getIDP(idpType: IDPType): IDPManager {
    when(idpType) {
      IDPType.OIDC -> return OIDCManager
    }
  }
}
