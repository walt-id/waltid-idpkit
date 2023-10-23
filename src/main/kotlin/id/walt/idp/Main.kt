package id.walt.idp

import com.github.ajalt.clikt.core.subcommands
import id.walt.cli.*
import id.walt.cli.did.*
import id.walt.idp.cli.*
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.context.ContextManager
import id.walt.webwallet.backend.context.WalletContextManager

fun main(args: Array<String>) {
    ServiceMatrix("service-matrix.properties")
    ServiceRegistry.registerService<ContextManager>(WalletContextManager)
    
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")
    System.out.println("------------------------------------------------------------\n")

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
            ),
            ClientRegistryCmd().subcommands(
                RegisterClientCmd(),
                ListClientCmd(),
                GetClientCmd(),
                RemoveClientCmd(),
                ClientRegistrationTokenCmd()
            )
        )
    ).main(args)
}
