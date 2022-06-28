package id.walt.idp

import com.github.ajalt.clikt.core.subcommands
import id.walt.cli.*
import id.walt.idp.cli.ConfigCmd
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.context.ContextManager
import id.walt.idp.cli.IDPCmd
import id.walt.idp.cli.RunCmd
import id.walt.webwallet.backend.context.WalletContextManager
import io.javalin.apibuilder.ApiBuilder.*

fun main(args: Array<String>) {
  ServiceMatrix("service-matrix.properties")
  ServiceRegistry.registerService<ContextManager>(WalletContextManager)

  IDPCmd().subcommands(
    RunCmd(),
    ConfigCmd().subcommands(
      KeyCommand().subcommands(
        GenKeyCommand(),
        ListKeysCommand(),
        ImportKeyCommand(),
        ExportKeyCommand()
      ),
      DidCommand().subcommands(
        CreateDidCommand(),
        ResolveDidCommand(),
        ListDidsCommand(),
        ImportDidCommand()
      ),
      EssifCommand().subcommands(
        EssifOnboardingCommand(),
        EssifAuthCommand(),
//                        EssifVcIssuanceCommand(),
//                        EssifVcExchangeCommand(),
        EssifDidCommand().subcommands(
          EssifDidRegisterCommand()
        )
      ),
      VcCommand().subcommands(
        VcIssueCommand(),
        PresentVcCommand(),
        VerifyVcCommand(),
        ListVcCommand(),
        VerificationPoliciesCommand().subcommands(
          ListVerificationPoliciesCommand(),
          CreateDynamicVerificationPolicyCommand(),
          RemoveDynamicVerificationPolicyCommand()
        ),
        VcTemplatesCommand().subcommands(
          VcTemplatesListCommand(),
          VcTemplatesExportCommand()
        ),
        VcImportCommand()
      )
    )
  ).main(args)
}
