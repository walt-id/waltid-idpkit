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
import kotlinx.serialization.json.Json
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object SiwaManager {
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


  fun verifySignature(session: OIDCSession, message: String, publicKey: String, signature: String): Boolean{

    val nonce= getNonce(message)
    if (session.siweSession?.nonce != nonce) {
      return false;
    }
    if (SiweManager.nonceBlacklists.contains(nonce)) {
      return false
    }
    SiweManager.nonceBlacklists.add(nonce)


    return runBlocking {
      val result = client.get("${IDPConfig.config.jsProjectExternalUrl}/algorand/signature/verification?publicKey=${publicKey}&signature=${URLEncoder.encode(signature, StandardCharsets.UTF_8)}&message=${URLEncoder.encode(message, StandardCharsets.UTF_8)}") {
      }.body<Boolean>()
      return@runBlocking result
    }
  }



  fun getAddress(message:String): String{
    val regex = Regex("Public Key: ([A-Z0-9]+)\\s*\\.\\s*Date:")
    val matchResult = regex.find(message)
    val publicKey = matchResult?.groupValues?.get(1)
    return publicKey!!
  }

  fun getNonce(message: String): String{
    val nonce= message.split(".").last().split(":").last().trim()
    return nonce
  }
  fun getPublicKey(message: String): String {
    val regex = Regex("Public Key: ([A-Z0-9]+)\\s*\\.\\s*Date:")
    val matchResult = regex.find(message)
    val publicKey = matchResult?.groupValues?.get(1)
    return publicKey!!
  }
}
