package id.walt.idp.context

import id.walt.WALTID_DATA_ROOT
import id.walt.services.context.Context
import id.walt.services.hkvstore.FileSystemHKVStore
import id.walt.services.hkvstore.FilesystemStoreConfig
import id.walt.services.keystore.HKVKeyStoreService
import id.walt.services.vcstore.HKVVcStoreService
import id.walt.webwallet.backend.context.UserContext

object ContextFactory {
    val contexts: MutableMap<String, Context> = mutableMapOf()

    fun getContextFor(id: ContextId): Context {
        return getDefaultContext(id.name)
    }

    fun getDefaultContext(id: String): Context {
        return contexts[id] ?: UserContext(
            contextId = id,
            hkvStore = FileSystemHKVStore(FilesystemStoreConfig("$WALTID_DATA_ROOT/data/${id}")),
            keyStore = HKVKeyStoreService(),
            vcStore = HKVVcStoreService()
        ).also {
            contexts[id] = it
        }
    }
}
