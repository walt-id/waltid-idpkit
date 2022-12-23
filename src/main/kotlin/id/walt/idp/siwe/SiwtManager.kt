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
            val result = client.get("${IDPConfig.config.jsProjectExternalUrl}/tezos/signature/verification?publicKey=${publicKey}&signature=${signature}&message=${URLEncoder.encode(message, StandardCharsets.UTF_8)}") {
            }.body<Boolean>()
            return@runBlocking result
        }
    }

    fun getAddress(message:String): String{
        val address= message.split(".").get(0).split(":").last().trim()
        return address
    }

    fun getNonce(message: String): String{
        val nonce= message.split(".").last().split(":").last().trim()
        return nonce
    }

    fun getPublicKey(message: String): String{
        val nonce= message.split(".").get(1).split(":").last().trim()
        return nonce
    }
}
