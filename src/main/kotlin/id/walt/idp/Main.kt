package id.walt.idp

import id.walt.idp.oidc.OIDCController
import id.walt.idp.rest.IDPRestAPI
import id.walt.servicematrix.ServiceMatrix
import id.walt.verifier.backend.VerifierController
import id.walt.webwallet.backend.rest.RestAPI
import io.javalin.apibuilder.ApiBuilder.*

fun main(args: Array<String>) {
  ServiceMatrix("service-matrix.properties")
  IDPRestAPI.start()
}
