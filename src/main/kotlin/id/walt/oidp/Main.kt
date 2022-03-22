package id.walt.oidp

import id.walt.oidp.oidc.OIDCController
import id.walt.servicematrix.ServiceMatrix
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.apibuilder.ApiBuilder.*

fun main(args: Array<String>) {
  ServiceMatrix("service-matrix.properties")

  RestAPI.apiTitle = "walt.id OpenID Provider"
  RestAPI.start("localhost", 8080) {
    path("api") {
      path("oidc") {
        OIDCController.routes
      }
      path("siop") {
        VerifierController.routes
      }
    }
  }

}
