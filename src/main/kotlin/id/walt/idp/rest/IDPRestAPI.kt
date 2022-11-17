package id.walt.idp.rest

import id.walt.idp.nfts.NFTController
import id.walt.idp.oidc.OIDCController
import id.walt.idp.oidc.OIDCManager
import id.walt.idp.siwe.SIWEController
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder.get
import io.javalin.apibuilder.ApiBuilder.path
import io.javalin.http.staticfiles.Location
import mu.KotlinLogging

object IDPRestAPI {
    var _javalin: Javalin? = null
    private val log = KotlinLogging.logger { }

    fun start(bindAddress: String = "localhost", port: Int = 8080) {
        RestAPI.apiTitle = "walt.id IDP Kit"
        _javalin = RestAPI.start(bindAddress, port, IDPAccessManager) {

            path("verifier-api", VerifierController::routes)

            path("api") {
                get("openIdRequestUri", OIDCManager::getIdpKitOpenIdRequestUri)
                path("oidc", OIDCController::routes)
                path("siop", VerifierController::routes)
                path("nft", NFTController::routes)
                path("siwe", SIWEController::routes)
            }
        }.apply {
            _conf.addStaticFiles {
                it.location = Location.CLASSPATH
                it.directory = "/app"
                it.hostedPath = "/"
            }
            _conf.addSinglePageRoot("/", "/app/index.html")
            exception(IllegalStateException::class.java) { e, ctx ->
                log.error { "ILLEGAL STATE EXCEPTION DURING HANDLING:" }
                e.printStackTrace()
                ctx.json(mapOf("error" to true, "message" to e.message))
            }
        }
    }

    fun stop() {
        _javalin?.stop()
        _javalin?.close()
        _javalin = null
    }
}
