package id.walt.idp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.groups.mutuallyExclusiveOptions
import com.github.ajalt.clikt.parameters.groups.required
import com.github.ajalt.clikt.parameters.groups.single
import com.github.ajalt.clikt.parameters.options.convert
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import id.walt.idp.oidc.OIDCManager
import id.walt.issuer.backend.IssuerManager
import id.walt.services.context.Context
import id.walt.verifier.backend.VerifierManager
import id.walt.webwallet.backend.context.UserContext
import id.walt.webwallet.backend.context.UserContextLoader
import id.walt.webwallet.backend.context.WalletContextManager
import mu.KotlinLogging

class ConfigCmd : CliktCommand(name = "config", help = "Configure or setup dids, keys, etc.") {

  private val log = KotlinLogging.logger {}

  val context : Context by mutuallyExclusiveOptions(
    option("--oidc", help = "Configure OIDC context").flag().convert { if(it) OIDCManager.oidcContext; else null },
    option("--siop", help = "Configure SIOP verifier context").flag().convert { if(it) VerifierManager.getService().verifierContext; else null }
  ).single().required()

  override fun run() {
    log.info("Running in context of: $context")
    WalletContextManager.setCurrentContext(context)
  }
}
