package id.walt.idp.siwe

import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCSession
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

@Serializable
data class SignatureVerificationResult(
  val result: Boolean
)

object SiwtManager {

  val client = HttpClient(CIO.create { requestTimeout = 0 }) {
    install(ContentNegotiation) {
      json(Json {
        ignoreUnknownKeys = true
      })
    }
    install(Logging) {
      logger = Logger.SIMPLE
      level = LogLevel.ALL
    }
    expectSuccess = false
  }

  fun verifySignature(session: OIDCSession, message: String, publicKey: String, signature: String): Boolean {

    val nonce = getNonce(message)
    if (session.siweSession?.nonce != nonce) {
      return false;
    }
    if (SiweManager.nonceBlacklists.contains(nonce)) {
      return false
    }
    SiweManager.nonceBlacklists.add(nonce)
    return runBlocking {
      val result = client.get(
        "${IDPConfig.config.jsProjectExternalUrl}/tezos/signature/verification?publicKey=${publicKey}&signature=${signature}&message=${
          URLEncoder.encode(
            message,
            StandardCharsets.UTF_8
          )
        }"
      ) {
      }.body<Boolean>()
      return@runBlocking result
    }
  }

  fun getAddress(message: String): String {
    val addressRegex = "tz\\w{34}".toRegex()
    val addressMatch = addressRegex.find(message)!!
    return addressMatch.value
  }

  fun getNonce(message: String): String {
    val nonce = message.split(".").last().split(":").last().trim()
    return nonce
  }

  fun getPublicKey(message: String): String {
    val publicKeyRegex = "edpk\\w{50}".toRegex()
    val publicKeyMatch = publicKeyRegex.find(message)

    if (publicKeyMatch == null || publicKeyMatch.value.isNullOrEmpty()) {
      val publicKeyRegex1 = "sppk\\w{51}".toRegex()
      val publicKeyMatch1 = publicKeyRegex1.find(message)
      if (publicKeyMatch1 == null || publicKeyMatch1.value.isNullOrEmpty()) {
        val publicKeyRegex2 = "p2pk\\w{51}".toRegex()
        val publicKeyMatch2 = publicKeyRegex2.find(message) ?: throw Exception("Key algorithm not supported")
        return publicKeyMatch2.value
      }
      return publicKeyMatch1.value
    }
    return publicKeyMatch.value
  }
}
