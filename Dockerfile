FROM openjdk:17-jdk-slim as buildstage
COPY ./ /
RUN ./gradlew installDist

FROM openjdk:17-jdk-slim
COPY service-matrix.properties /waltid-idpkit/
COPY signatory.conf /waltid-idpkit/
COPY --from=buildstage /build/install/ /

WORKDIR /waltid-idpkit
ENV WALTID_WALLET_BACKEND_BIND_ADDRESS=0.0.0.0
ENTRYPOINT ["/waltid-idpkit/bin/waltid-idpkit"]
