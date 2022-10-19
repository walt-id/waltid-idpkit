package id.walt.idp.siwe

class SiweResponseVerificationResult(
    val account: String,
    val sessionId: String,
    val valid: Boolean = false,
    val error: String? = null
) {
    val isValid
        get() = valid
}
