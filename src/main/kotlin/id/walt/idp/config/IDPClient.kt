package id.walt.idp.config

data class IDPClient (
  val clientId: String,
  val clientSecret: String,
  val redirectUris: Set<String>? = null,
  val allowAllRedirectUris: Boolean = false
    )
