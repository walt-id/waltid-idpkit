package id.walt.idp

import id.walt.idp.oidc.ClaimMapping
import id.walt.idp.oidc.ClaimMappings

val TEST_CLAIM_MAPPINGS = ClaimMappings(
  mappings = listOf(
    ClaimMapping(
      setOf("profile"),
      "name",
      "VerifiableId",
      "$.credentialSubject.firstName $.credentialSubject.familyName"
    ),
    id.walt.idp.oidc.ClaimMapping(
      setOf("profile"),
      "family_name",
      "VerifiableId",
      "$.credentialSubject.familyName"
    ),
    id.walt.idp.oidc.ClaimMapping(
      setOf("profile"),
      "given_name",
      "VerifiableId",
      "$.credentialSubject.firstName"
    ),
    id.walt.idp.oidc.ClaimMapping(
      setOf("profile"),
      "gender",
      "VerifiableId",
      "$.credentialSubject.gender"
    ),
    id.walt.idp.oidc.ClaimMapping(
      setOf("profile"),
      "birthdate",
      "VerifiableId",
      "$.credentialSubject.dateOfBirth"
    ),
    id.walt.idp.oidc.ClaimMapping(
      setOf("address"),
      "address",
      "VerifiableId",
      "$.credentialSubject.currentAddress[0]"
    )
  )
)
