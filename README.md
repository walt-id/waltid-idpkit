# IDP Kit

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=security_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=ncloc)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![CI/CD Workflow for walt.id IDO Kit](https://github.com/walt-id/waltid-idpkit/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/walt-id/waltid-idpkit/actions/workflows/build.yml)

The IDP Kit enables you to launch an OIDC compliant identity provider that utilizes the OIDC-SIOPv2 protocol and/or NFT blockchain APIs to retrieve identity data or NFT metadata via a suitable wallet.
Identity data from a Web3 or SSI wallet can be provided as OIDC user info and/or is mapped to standard OIDC claims.


## Simple authentication flow with IDP Kit

The following picture shows a simple OIDC authentication flow between the end user application and the IDP Kit:

![IDP Kit Concept](./idpkit-concept.png)

Please visit our documentation-section for a more in-depth docu regarding concepts, architecture and usage at: https://docs.walt.id/v/idpkit

## Documentation

- Docs: https://docs.walt.id/v/idpkit
- Quick Start (Build & run the SSI Kit with Docker or with **ssikit.sh**): https://docs.walt.id/v/ssikit/getting-started/quick-start
- CLI Tool: https://docs.walt.id/v/ssikit/getting-started/cli-command-line-interface
- APIs: https://docs.walt.id/v/ssikit/getting-started/rest-apis

## Relevant Standards

- Self-Issued OpenID Provider v2 https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
- OpenID Connect for Verifiable Presentations https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-07.html
- OpenID Connect for Verifiable Credential Issuance https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- Verifiable Credentials Data Model 1.0 https://www.w3.org/TR/vc-data-model/
- Decentralized Identifiers (DIDs) v1.0 https://w3c.github.io/did-core/

## License

```
Copyright ((C)) 2022 walt.id GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
