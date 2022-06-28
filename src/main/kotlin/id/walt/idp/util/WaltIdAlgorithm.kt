package id.walt.idp.util

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.nimbusds.jose.util.Base64URL
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.services.crypto.CryptoService
import id.walt.webwallet.backend.context.UserContext
import id.walt.webwallet.backend.context.WalletContextManager

class WaltIdAlgorithm(val keyId: KeyId, val context: UserContext, alg: KeyAlgorithm)
  : Algorithm(when(alg) {
      KeyAlgorithm.EdDSA_Ed25519 -> "EdDSA"
      KeyAlgorithm.ECDSA_Secp256k1 -> "ES256K"
      KeyAlgorithm.RSA -> "RS256"
    }, "Use key from SSIKit key service") {
  override fun verify(jwt: DecodedJWT?) {
    if(!WalletContextManager.runWith(context) {
        CryptoService.getService().verify(keyId, Base64URL.from(jwt!!.signature).decode(), "${jwt.header}.${jwt.payload}".encodeToByteArray())
    }) {
      throw JWTVerificationException("Signature not verified")
    }
  }

  override fun sign(contentBytes: ByteArray?): ByteArray {
    return WalletContextManager.runWith(context) {
      CryptoService.getService().sign(keyId, contentBytes!!)
    }

  }
}
