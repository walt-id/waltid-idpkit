<template>
    <div class="d-flex justify-content-center text-white vh-100 vw-100">
        <div class="my-auto">
            <div class="text-center">
                <div class="text-white h1">walt.id IDP Kit</div>
            </div>

            <div class="text-center">
                <a v-if="requestInfo && requestInfo.requestId" class="btn btn-success" @click="redirectToWebWallet('walt.id')">Click
                    to login with Web Wallet</a> <a v-else class="btn btn-danger" @click="redirectBack">Return to
                previous page</a>
            </div>

            <hr>

            <div>
                <div v-if="requestInfo && requestInfo.requestId" class="text-center">
                    <h2>Or scan this code with your mobile identity wallet:</h2>
                </div>
                <div v-else>
                    <h2>Invalid request (Timed out or doesn't exist).</h2>
                </div>
                <div class="text-center">
                    <canvas :id="'qr-code'"/>
                </div>
                <div v-if="requestInfo && requestInfo.requestId && requestInfo.url" class="text-center small">
                    Request ID: {{ requestInfo.requestId }}
                    <pre><code>{{ requestInfo.url }}</code></pre>
                </div>
            </div>

        </div>
    </div>
</template>

<script>
import QRious from "qrious"

export default {
    name: 'ShareCredential',
    async asyncData({$axios, route}) {
        if (route.query.state || route.params.state) {
            let state = route.query.state ? route.query.state : route.params.state
            console.log("Using state: " + state)

            const requestInfo = await $axios.$get('/api/oidc/web-api/getWalletRedirectAddress?walletId=x-device&state=' + state)

            if (requestInfo) {
                console.log(requestInfo)
                return {requestInfo, state}
            } else return null
        } else {
            console.log("No state in params!")
            return null
        }
    },
    mounted() {
        if (this.requestInfo && this.requestInfo.url) {
            new QRious({
                element: document.getElementById('qr-code'),
                value: this.requestInfo.url,
                size: 300
            })
        }
        let reqTimer = setInterval(async () => {
        let response = await fetch("/verifier-api/default/verify/isVerified?state=" + this.requestInfo.requestId);

        if (response.status === 200) {
            window.clearTimeout(reqTimer);

            window.location = await response.text();
        }
    }, 1000)
    },
    methods: {
        async redirectToWebWallet(walletId) {
            console.log("redirect to wallet", walletId, "state", this.state)
            let walletReqInfo = await this.$axios.$get('/api/oidc/web-api/getWalletRedirectAddress?walletId=' + walletId + '&state=' + this.state)
            if(walletReqInfo != null) {
                console.log("Wallet url: " + walletReqInfo.url)

                window.location = walletReqInfo.url
            } else {
                console.log("No wallet req info")
            }
        },
        redirectBack: function () {
            window.history.back()
        }
    }
}
</script>

<style></style>
