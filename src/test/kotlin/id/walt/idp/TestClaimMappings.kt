package id.walt.idp

import id.walt.idp.oidc.VCClaimMapping
import id.walt.idp.oidc.ClaimMappings

val TEST_CLAIM_MAPPINGS = ClaimMappings(
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
