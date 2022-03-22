package id.walt.oidp.config

import com.beust.klaxon.Klaxon
import id.walt.webwallet.backend.config.ExternalHostnameUrl
import id.walt.webwallet.backend.config.externalHostnameUrlValueConverter
import java.io.File

data class OIDPConfig (
  @ExternalHostnameUrl val externalUrl: String = "http://localhost:6000"
    ) {
  companion object {
    val CONFIG_FILE = "${id.walt.WALTID_DATA_ROOT}/config/oidp-config.json"
    lateinit var config: OIDPConfig
    init {
      val cf = File(CONFIG_FILE)
      if(cf.exists()) {
        config = Klaxon().fieldConverter(ExternalHostnameUrl::class, externalHostnameUrlValueConverter).parse(cf) ?: OIDPConfig()
      } else {
        config = OIDPConfig()
      }
    }
  }
}
