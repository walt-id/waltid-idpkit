package id.walt.idp.oidc

import com.jayway.jsonpath.JsonPath
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.Scope
import io.javalin.http.BadRequestResponse

abstract class ClaimMapping(
    val scope: Set<String>,
    val claim: String
) {
    abstract fun fillClaims(verificationResult: ResponseVerificationResult, claimBuilder: JWTClaimsSet.Builder)
    abstract val authorizationMode: OIDCManager.AuthorizationMode
}

class VCClaimMapping (
    scope: Set<String>,
    claim: String,
    val credentialType: String,
    val valuePath: String
) : ClaimMapping(scope, claim) {
    override fun fillClaims(verificationResult: ResponseVerificationResult, claimBuilder: JWTClaimsSet.Builder) {
        val credential = verificationResult.siopResponseVerificationResult?.vp_token?.verifiableCredential?.firstOrNull{ c -> c.type.contains(credentialType) } ?: throw BadRequestResponse("vp_token from SIOP response doesn't contain required credentials")
        val jp = JsonPath.parse(credential.json)
        val value = valuePath.split(" ").map { jp.read<Any>(it) }.joinToString(" ")
        claimBuilder.claim(claim, value)
    }

    override val authorizationMode: OIDCManager.AuthorizationMode
        get() = OIDCManager.AuthorizationMode.SIOP
}

class NFTClaimMapping (
    scope: Set<String>,
    claim: String,
    val chain: String,
    val smartContractAddress: String,
    val trait: String
) : ClaimMapping(scope, claim) {
    override fun fillClaims(verificationResult: ResponseVerificationResult, claimBuilder: JWTClaimsSet.Builder) {
        val attribute = verificationResult.nftresponseVerificationResult?.metadata?.attributes?.firstOrNull() { a -> a.trait_type == trait } ?: throw BadRequestResponse("Requested nft metadata train not found in verification response")
        claimBuilder.claim(trait, attribute.value)
    }

    override val authorizationMode: OIDCManager.AuthorizationMode
        get() = OIDCManager.AuthorizationMode.NFT
}


class ClaimMappings(
    val vc_mappings: List<VCClaimMapping>? = null,
    val nft_mappings: List<NFTClaimMapping>? = null
) {
    fun allMappings(): List<ClaimMapping> {
        return (vc_mappings ?: listOf()).plus(nft_mappings ?: listOf())
    }

    fun mappingsForScope(scope: Scope.Value): List<ClaimMapping> {
        return allMappings()
                .filter { m -> m.scope.contains(scope.value) }
    }

    fun mappingsForClaim(claim: String): List<ClaimMapping> {
        return allMappings()
                .filter { m -> m.claim == claim }
    }

    fun credentialTypesForScope(scope: Scope.Value): Set<String> {
        return vc_mappings?.filter { m -> m.scope.contains(scope.value) }
                ?.map { m -> m.credentialType }?.toSet()
                ?: setOf()
    }

    fun credentialTypesForClaim(claim: String): Set<String> {
        return vc_mappings?.filter { m -> m.claim == claim }
                ?.map { m -> m.credentialType }?.toSet()
                ?: setOf()
    }
}
