package id.walt.idp.rest

import id.walt.idp.oidc.OIDCController
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.apibuilder.ApiBuilder

object IDPRestAPI {
  fun start() {
    RestAPI.apiTitle = "walt.id OpenID Provider"
    RestAPI.start("localhost", 8080, IDPAccessManager) {
      ApiBuilder.path("api") {
        ApiBuilder.path("oidc") {
          OIDCController.routes
        }
        ApiBuilder.path("siop") {
          VerifierController.routes
        }
      }
    }
  }
}
