package id.walt.idp

import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import id.walt.idp.config.IDPConfig
import id.walt.idp.oidc.OIDCClientRegistry
import id.walt.idp.rest.IDPRestAPI
import id.walt.model.DidMethod
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.context.ContextManager
import id.walt.services.did.DidService
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.verifier.backend.VerifierConfig
import id.walt.webwallet.backend.context.WalletContextManager
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.AnnotationSpec
import io.mockk.every
import io.mockk.mockkObject
import java.net.URI
import java.util.*

class OIDCClientRegistrationTest: OIDCTestBase() {

  override fun customInit() {

  }

  @Test
  fun testClientRegistration() {

  }
}
