package id.walt.idp

import id.walt.idp.config.ClaimConfig
import id.walt.idp.config.VCClaimMapping

val TEST_CLAIM_MAPPINGS = ClaimConfig(
    vc_mappings = listOf(
        VCClaimMapping(
            setOf("profile"),
            "name",
            "VerifiableId",
            "$.credentialSubject.firstName $.credentialSubject.familyName"
        ),
        VCClaimMapping(
            setOf("profile"),
            "family_name",
            "VerifiableId",
            "$.credentialSubject.familyName"
        ),
        VCClaimMapping(
            setOf("profile"),
            "given_name",
            "VerifiableId",
            "$.credentialSubject.firstName"
        ),
        VCClaimMapping(
            setOf("profile"),
            "gender",
            "VerifiableId",
            "$.credentialSubject.gender"
        ),
        VCClaimMapping(
            setOf("profile"),
            "birthdate",
            "VerifiableId",
            "$.credentialSubject.dateOfBirth"
        ),
        VCClaimMapping(
            setOf("address"),
            "address",
            "VerifiableId",
            "$.credentialSubject.currentAddress[0]"
        )
    )
)
