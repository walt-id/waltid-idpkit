package id.walt.idp.config

import com.beust.klaxon.Klaxon
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import id.walt.idp.oidc.ClaimMappings
import id.walt.idp.oidc.OIDCManager
import id.walt.webwallet.backend.config.ExternalHostnameUrl
import id.walt.webwallet.backend.config.externalHostnameUrlValueConverter
import java.io.File

data class IDPConfig (
  @ExternalHostnameUrl val externalUrl: String = "http://localhost:6000",
  val keyId: String = "",
  val claimMappings: ClaimMappings? = null,
  val openClientRegistration: Boolean = false,
  val fallbackAuthorizationMode: OIDCManager.AuthorizationMode = OIDCManager.AuthorizationMode.SIOP
    ) {
  companion object {
    val CONFIG_FILE = "${id.walt.WALTID_DATA_ROOT}/config/idp-config.json"
    lateinit var config: IDPConfig
    init {
      val cf = File(CONFIG_FILE)
      if(cf.exists()) {
        config = Klaxon().fieldConverter(ExternalHostnameUrl::class, externalHostnameUrlValueConverter).parse(cf) ?: IDPConfig()
      } else {
        config = IDPConfig()
      }
    }
  }
}
