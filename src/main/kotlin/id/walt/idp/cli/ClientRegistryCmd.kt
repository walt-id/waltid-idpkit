package id.walt.idp.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import id.walt.common.prettyPrint
import id.walt.idp.oidc.OIDCClientRegistry
import id.walt.idp.oidc.OIDCManager
import java.net.URI

class ClientRegistryCmd: CliktCommand(name = "clients", help = "Manage registered OIDC clients") {
  override fun run() {
  }
}

class RegisterClientCmd: CliktCommand(name = "register", help = "Register new OIDC client") {
  val name: String? by option("-n", "--name", help = "Client Name")
  val redirectUris: List<String> by option("-r", "--redirect-uri", help = "Redirect URI, can be specified multiple times").multiple()
  val allRedirectUris: Boolean by option("--all-redirect-uris", help = "Allow all redirect URIs for this client").flag(default = false)
  val updateClient: String? by option("-u", "--update", help = "Update existing client with given ID")
  override fun run() {
    val clientMetadata = ClientMetadata().apply {
      name = name
      redirectionURIs = redirectUris.map { URI(it) }.toSet()
    }
    try {
      val clientInfo = if (updateClient.isNullOrEmpty()) {
        OIDCClientRegistry.registerClient(clientMetadata, allRedirectUris)
      } else {
        OIDCClientRegistry.updateClient(updateClient!!, clientMetadata, allRedirectUris)
      }
      println("Created client registration:")
      println("client_id: ${clientInfo.id.value}")
      println("client_secret: ${clientInfo.secret.value}")
    } catch (exc: Exception) {
      println("Error creating or updating client registration: ${exc.message}")
    }
  }
}

class ListClientCmd: CliktCommand(name = "list", help = "List OIDC clients") {
  override fun run() {
    OIDCClientRegistry.listClientIds().forEach {
      val clientInfo = OIDCClientRegistry.getClient(it).get()
      println("* ${clientInfo.id.value}:\n${clientInfo.toJSONObject().toJSONString().prettyPrint()}\n--------------------")
    }
  }
}

class GetClientCmd: CliktCommand(name = "get", help = "Get OIDC client") {
  val clientId: String by option("-i", "--id", help = "Client ID").required()
  override fun run() {
    val clientInfo = OIDCClientRegistry.getClient(clientId)
    if(clientInfo.isPresent) {
      println("* ${clientInfo.get().id.value}:\n${clientInfo.get().toJSONObject().toJSONString().prettyPrint()}\n--------------------")
    } else {
      println("Client with the given ID not found.")
    }
  }
}

class RemoveClientCmd: CliktCommand(name = "remove", help = "Remove OIDC client") {
  val clientId: String by option("-i", "--id", help = "Client ID").required()
  override fun run() {
    try {
      OIDCClientRegistry.unregisterClient(clientId)
      println("Client removed")
    } catch (exc: Exception) {
      println("Error removing registered client: ${exc.message}")
    }
  }
}
