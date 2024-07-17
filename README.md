<div align="center">
 <h1>IDP Kit</h1>
 <span>by </span><a href="https://walt.id">walt.id</a>
 <p>Launch an OIDC compliant identity provider using SSI/NFTs<p>

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=security_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-idpkit&metric=ncloc)](https://sonarcloud.io/dashboard?id=walt-id_waltid-idpkit)
[![CI/CD Workflow for walt.id IDO Kit](https://github.com/walt-id/waltid-idpkit/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/walt-id/waltid-idpkit/actions/workflows/build.yml)

<a href="https://walt.id/community">
<img src="https://img.shields.io/badge/Join-The Community-blue.svg?style=flat" alt="Join community!" />
</a>
<a href="https://twitter.com/intent/follow?screen_name=walt_id">
<img src="https://img.shields.io/twitter/follow/walt_id.svg?label=Follow%20@walt_id" alt="Follow @walt_id" />
</a>

</div>

## Compatibility Notice & Updates
Please note that the IDP-Kit currently only works with the [SSI-Kit](https://github.com/walt-id/waltid-ssikit), [Wallet-Kit](https://github.com/walt-id/waltid-walletkit) and [NFT-Kit](https://github.com/walt-id/waltid-nftkit), but is not yet compatible with our new products under [The Community Stack](https://walt.id/blog/p/community-stack). If you are intersted in using it with our new stack, please reach out [here](https://walt.id/discord).


## Getting Started

- [REST Api](https://docs.walt.id/v/idpkit/getting-started/rest-apis) - Launch your OIDC compliant identity provider.
- [CLI](https://docs.walt.id/v/idpkit/getting-started/cli) - Configure your OIDC compliant identity provider. 
- [Maven/Gradle Dependency](https://docs.walt.id/v/idpkit/getting-started/dependency-jvm) - Use the functions of the IDP Kit in a Kotlin/Java project.

Checkout the [Official Documentation](https://docs.walt.id/v/idpkit/idpkit/readme), to find out more.

## What is the IDP Kit?

The IDP Kit enables you to launch an OIDC compliant identity provider that utilizes the OIDC-SIOPv2 protocol and/or NFT blockchain APIs to retrieve identity data or NFT metadata via a suitable wallet.
Identity data from a Web3 or SSI wallet can be provided as OIDC user info and/or is mapped to standard OIDC claims.


## Simple authentication flow with IDP Kit

The following picture shows a simple OIDC authentication flow between the end user application and the IDP Kit:

![IDP Kit Concept](./ipdkit-concept.png)

Please visit our [documentation-section](https://docs.walt.id/v/idpkit) to learn more about concepts, architecture and usage.

## Join the community

* Connect and get the latest updates: [Discord](https://discord.gg/AW8AgqJthZ) | [Newsletter](https://walt.id/newsletter) | [YouTube](https://www.youtube.com/channel/UCXfOzrv3PIvmur_CmwwmdLA) | [Twitter](https://mobile.twitter.com/walt_id)
* Get help, request features and report bugs: [GitHub Discussions](https://github.com/walt-id/.github/discussions)

## Relevant Standards

- [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
- [OpenID Connect for Verifiable Presentations](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-07.html)
- [OpenID Connect for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [Verifiable Credentials Data Model 1.0](https://www.w3.org/TR/vc-data-model/)
- [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/)

## License

Licensed under the [Apache License, Version 2.0](https://github.com/walt-id/waltid-ssikit/blob/master/LICENSE)
