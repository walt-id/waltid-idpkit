<template>
    <div class="d-flex justify-content-center text-white vh-100 vw-100">
        <div class="my-auto">
            <div class="text-center">
                <div class="text-white h1">walt.id IDP Kit</div>
            </div>

            <div class="text-center">
                <a class="btn btn-success" v-on:click="redirectToWebWallet">Click to login with Web Wallet</a>
            </div>

            <hr>

            <div>
                <div class="text-center">
                    <h2>Or scan this code with your mobile identity wallet:</h2>
                </div>
                <div class="text-center">
                    <canvas :id="'qr-code'"/>
                </div>
                <div class="text-center small">
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
        const requestInfo = await $axios.$get('/api/openIdRequestUri?state=' + route.params.state)

        let reqTimer = setInterval(async () => {
            let response = await fetch("/verifier-api/verify/isVerified?state=" + requestInfo.requestId);

            if (response.status === 200) {
                window.clearTimeout(reqTimer);

                window.location = await response.text();
            }
        }, 1000)

        console.log(requestInfo)
        return {requestInfo}
    },
    mounted() {
        new QRious({
            element: document.getElementById('qr-code'),
            value: this.requestInfo.url,
            size: 300
        })
    },
    methods: {
        redirectToWebWallet: function() {

            let reqUrl = this.requestInfo.url
            let reqParams = reqUrl.substring(reqUrl.indexOf('?'), reqUrl.length - 1)
            let fullUrl = "https://wallet.walt-test.cloud/api/siop/initiatePresentation/?" + reqParams
            console.log("Full url: " + fullUrl)

            window.location = fullUrl
        }
    }
}
</script>

<style>
</style>
