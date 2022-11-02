FROM docker.io/openjdk:17-slim-buster as buildstage
#RUN apt-get update && apt-get install -y git nodejs npm && npm install -g yarn
COPY ./ /
RUN ./gradlew installDist

FROM waltid/waltid_iota_identity_wrapper:latest as iota_wrapper
FROM openjdk:17-jdk-slim
ADD https://openpolicyagent.org/downloads/v0.41.0/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod 755 /usr/local/bin/opa
COPY --from=iota_wrapper /usr/local/lib/libwaltid_iota_identity_wrapper.so /usr/local/lib/libwaltid_iota_identity_wrapper.so
RUN ldconfig

COPY service-matrix.properties /waltid-idpkit/
COPY signatory.conf /waltid-idpkit/
COPY --from=buildstage /build/install/ /

WORKDIR /waltid-idpkit
ENV WALTID_WALLET_BACKEND_BIND_ADDRESS=0.0.0.0
ENTRYPOINT ["/waltid-idpkit/bin/waltid-idpkit"]
