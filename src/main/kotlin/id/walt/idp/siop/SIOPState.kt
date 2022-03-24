package id.walt.idp.siop

import com.beust.klaxon.Klaxon
import id.walt.idp.IDPType
import java.nio.charset.StandardCharsets
import java.util.*

data class SIOPState (
  val idpType: IDPType,
  val idpSessionId: String
    ) {
  fun encode(): String = Base64.getUrlEncoder().encodeToString(Klaxon().toJsonString(this).toByteArray(StandardCharsets.UTF_8))

  companion object {
    fun decode(state: String): SIOPState? {
      return Klaxon().parse(String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8))
    }
  }
}
