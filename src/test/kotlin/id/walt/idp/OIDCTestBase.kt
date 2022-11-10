package id.walt.idp

import id.walt.idp.config.IDPConfig
import id.walt.idp.context.ContextFactory
import id.walt.idp.rest.IDPRestAPI
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.context.Context
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.InMemoryHKVStore
import id.walt.services.keystore.HKVKeyStoreService
import id.walt.services.vcstore.HKVVcStoreService
import id.walt.verifier.backend.VerifierConfig
import id.walt.webwallet.backend.context.UserContext
import id.walt.webwallet.backend.context.WalletContextManager
import io.kotest.core.spec.style.AnnotationSpec
import io.mockk.every
import io.mockk.mockkObject
import java.net.URI

abstract class OIDCTestBase : AnnotationSpec() {
    val OIDC_URI: URI = URI.create("http://localhost:8080/api/oidc")
    val contexts: MutableMap<String, Context> = mutableMapOf()

    @BeforeClass
    fun init() {
        ServiceMatrix("src/test/resources/service-matrix.properties")
        ServiceRegistry.registerService<ContextManager>(WalletContextManager)

        mockkObject(ContextFactory)
        every { ContextFactory.getContextFor(any()) } answers { c ->
            contexts[c.invocation.args.first().toString()] ?: UserContext(
                contextId = c.invocation.args.first().toString(),
                hkvStore = InMemoryHKVStore(),
                keyStore = HKVKeyStoreService(),
                vcStore = HKVVcStoreService()
            ).also { contexts[c.invocation.args.first().toString()] = it }
        }

        mockkObject(IDPConfig)
        every { IDPConfig.config } returns IDPConfig(
            externalUrl = "http://localhost:8080",
            "",
            claimConfig = TEST_CLAIM_MAPPINGS
        )

        mockkObject(VerifierConfig)
        every { VerifierConfig.config } returns VerifierConfig("http://localhost:8080", "http://localhost:8080/api/siop")

        customInit()

        IDPRestAPI.start()
    }

    @AfterClass
    fun deinit() {
        IDPRestAPI.stop()
    }

    abstract fun customInit()
}
