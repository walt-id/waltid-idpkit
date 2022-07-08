package id.walt.idp.rest

import id.walt.idp.nfts.NFTController
import id.walt.idp.oidc.OIDCController
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.apibuilder.ApiBuilder

object IDPRestAPI {
  fun start(bindAddress: String = "localhost", port: Int = 8080) {
    RestAPI.apiTitle = "walt.id OpenID Provider"
    RestAPI.start(bindAddress, port, IDPAccessManager) {
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
      }
    }
  }
}
