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
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonEncoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets


object siwfManager {

  val client = HttpClient(CIO.create{requestTimeout = 0}) {
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

  fun verifySignature(session: OIDCSession, message: String, signature: String): Boolean{


    val nonce= getNonce(message)
    if (session.siweSession?.nonce != nonce) {
      return false;
    }
    if (SiweManager.nonceBlacklists.contains(nonce)) {
      return false
    }
    SiweManager.nonceBlacklists.add(nonce)
    return runBlocking {
      val result = client.post("${IDPConfig.config.jsProjectExternalUrl}/flow/signature/verification?signature=${URLEncoder.encode(signature, StandardCharsets.UTF_8.toString())}&message=${URLEncoder.encode(message, StandardCharsets.UTF_8.toString())}") {

      }.body<Boolean>()
      return@runBlocking result
    }
  }
  fun getAddress(message:String): String{
    val address= message.split(" .").get(0).split(":").last().trim()
    return address
  }

  fun getNonce(message: String): String{
    val nonce= message.split(".").last().split(":").last().trim()
    return nonce
  }


}
