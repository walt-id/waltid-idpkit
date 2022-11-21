### Configuration

# set --build-args SKIP_TESTS=true to use
ARG SKIP_TESTS

# --- build-env
FROM docker.io/gradle:7.5-jdk as build-env

RUN apt-get update && apt-get install -y git nodejs npm && npm install -g yarn

WORKDIR /appbuild

COPY . /appbuild

# cache Gradle dependencies
VOLUME /home/gradle/.gradle

RUN if [ -z "$SKIP_TESTS" ]; \
    then echo "* Running full build" && gradle -i clean build installDist; \
    else echo "* Building but skipping tests" && gradle -i clean installDist -x test; \
    fi

# --- opa-env
FROM docker.io/openpolicyagent/opa:0.46.1-static as opa-env

# --- iota-env
FROM docker.io/waltid/waltid_iota_identity_wrapper:latest as iota-env

# --- app-env
FROM docker.io/eclipse-temurin:19 AS app-env

WORKDIR /app

COPY --from=opa-env /opa /usr/local/bin/opa
COPY --from=iota-env /usr/local/lib/libwaltid_iota_identity_wrapper.so /usr/local/lib/libwaltid_iota_identity_wrapper.so
RUN ldconfig


COPY --from=build-env /appbuild/build/install/waltid-idpkit /app/
COPY --from=build-env /appbuild/service-matrix.properties /app/
COPY --from=build-env /appbuild/config /app/config


WORKDIR /app
ENV WALTID_WALLET_BACKEND_BIND_ADDRESS=0.0.0.0
ENTRYPOINT ["/app/bin/waltid-idpkit"]
