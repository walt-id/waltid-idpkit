package id.walt.idp.oidc

import com.nimbusds.oauth2.sdk.Scope

data class ClaimMapping (
    val scope: Set<String>,
    val claim: String,
    val credentialType: String,
    val valuePath: String
    )

class ClaimMappings(
    val mappings: List<ClaimMapping>
) {
    fun mappingsForScope(scope: Scope.Value): List<ClaimMapping> {
        return mappings.filter { m -> m.scope.contains(scope.value) }
    }

    fun mappingsForClaim(claim: String): List<ClaimMapping> {
        return mappings.filter { m -> m.claim == claim }
    }

    fun credentialTypesForScope(scope: Scope.Value): Set<String> {
        return mappingsForScope(scope).map { m -> m.credentialType }.toSet()
    }

    fun credentialTypesForClaim(claim: String): Set<String> {
        return mappingsForClaim(claim).map { m -> m.credentialType }.toSet()
    }
}
