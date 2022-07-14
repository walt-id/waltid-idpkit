package id.walt.idp.oidc

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.client.ClientInformation
import com.nimbusds.oauth2.sdk.client.ClientMetadata
import com.nimbusds.oauth2.sdk.id.ClientID
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.HKVKey
import id.walt.services.hkvstore.HKVStoreService
import mu.KotlinLogging
import net.minidev.json.JSONObject
import net.minidev.json.JSONStyle
import net.minidev.json.parser.JSONParser
import java.util.*

object OIDCClientRegistry : CacheLoader<String, Optional<ClientInformation>>() {
  val log = KotlinLogging.logger {}
  private val clientsCache: LoadingCache<String, Optional<ClientInformation>> = CacheBuilder.newBuilder().build(this)

  const val CLIENT_REGISTRATION_ROOT = "oidc_clients"
  const val ALL_REDIRECT_URIS = "all_redirect_uris"

  override fun load(key: String): Optional<ClientInformation> {
    return Optional.ofNullable(
      ContextManager.runWith(OIDCManager.oidcContext) {
        log.info { "Loading OIDC client from store" }
        HKVStoreService.getService().getAsString(HKVKey(CLIENT_REGISTRATION_ROOT, key))?.let {
          log.debug { "Parsing OIDC client info" }
          ClientInformation.parse(JSONParser(-1).parse(it) as JSONObject?)
      }
    })
  }

  fun registerClient(clientMetadata: ClientMetadata, allRedirectUris: Boolean): ClientInformation {
    if(OIDCManager.checkClientCompatibility(clientMetadata)) {
      return createClientInfo(ClientID(), clientMetadata, allRedirectUris, Secret())
    }
    throw Exception("Client metadata not compatible with OIDC Manager")
  }

  fun getClient(clientId: String): Optional<ClientInformation> {
    return clientsCache[clientId]
  }

  private fun createClientInfo(clientId: ClientID, clientMetadata: ClientMetadata, allRedirectUris: Boolean, clientSecret: Secret):ClientInformation {
    log.info { "Creating/updating client: $clientId" }
    return ClientInformation(clientId, Date(), clientMetadata.apply { customFields[ALL_REDIRECT_URIS] = allRedirectUris }, clientSecret)
      .also {
        ContextManager.runWith(OIDCManager.oidcContext) {
          HKVStoreService.getService().put(HKVKey(CLIENT_REGISTRATION_ROOT, it.id.value), it.toJSONObject().toString(JSONStyle.LT_COMPRESS))
        }
        clientsCache.put(it.id.value, Optional.of(it))
      }
  }

  fun updateClient(clientId: String, clientMetadata: ClientMetadata, allRedirectUris: Boolean): ClientInformation {
    val clientInfo = getClient(clientId).orElseThrow { Exception("Client with given client_id doesn't exist") }
    if(OIDCManager.checkClientCompatibility(clientMetadata)) {
      return createClientInfo(clientInfo.id, clientMetadata, allRedirectUris, clientInfo.secret)
    }
    throw Exception("Client metadata not compatible with OIDC Manager")
  }

  fun unregisterClient(clientId: String) {
    val clientInfo = getClient(clientId).orElseThrow { Exception("Client with given client_id doesn't exist") }
    log.info { "Unregistering client $clientId" }
    ContextManager.runWith(OIDCManager.oidcContext) {
      HKVStoreService.getService().delete(HKVKey(CLIENT_REGISTRATION_ROOT, clientId))
    }
    clientsCache.invalidate(clientId)
  }

  fun listClientIds(): Set<String> {
    return ContextManager.runWith(OIDCManager.oidcContext) {
      HKVStoreService.getService().listChildKeys(HKVKey(CLIENT_REGISTRATION_ROOT))
    }.map { k -> k.name }.toSet()
  }
}
