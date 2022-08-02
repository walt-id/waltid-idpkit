package id.walt.idp.rest

import id.walt.idp.nfts.NFTController
import id.walt.idp.oidc.OIDCController
import id.walt.idp.siwe.SIWEController
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.Javalin
import io.javalin.apibuilder.ApiBuilder
import io.javalin.http.staticfiles.Location

object IDPRestAPI {
  var _javalin: Javalin? = null
  fun start(bindAddress: String = "localhost", port: Int = 8080) {
    RestAPI.apiTitle = "walt.id IDP Kit"
    _javalin = RestAPI.start(bindAddress, port, IDPAccessManager) {
      ApiBuilder.path("api") {
        ApiBuilder.path("oidc") {
          OIDCController.routes
        }
        ApiBuilder.path("siop") {
          VerifierController.routes
        }
        ApiBuilder.path("nft") {
          NFTController.routes
        }
        ApiBuilder.path("siwe") {
          SIWEController.routes
        }
      }
    }.apply {
      _conf.addStaticFiles {
        it.location = Location.CLASSPATH
        it.directory = "/app"
        it.hostedPath = "/"
      }
      _conf.addSinglePageRoot("/", "/app/index.html")
    }
  }

  fun stop() {
    _javalin?.stop()
    _javalin?.close()
    _javalin = null
  }
}
