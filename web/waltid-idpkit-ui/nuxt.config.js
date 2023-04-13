export default {
    // Target: https://go.nuxtjs.dev/config-target
    target: 'static',
    ssr: false,

    // Global page headers: https://go.nuxtjs.dev/config-head
    head: {
        title: 'waltid-idpkit-ui',
        htmlAttrs: {
            lang: 'en'
        },
        meta: [
            {charset: 'utf-8'},
            {name: 'viewport', content: 'width=device-width, initial-scale=1'},
            {hid: 'description', name: 'description', content: ''},
            {name: 'format-detection', content: 'telephone=no'}
        ],
        link: [
            {rel: 'icon', type: 'image/x-icon', href: '/favicon.ico'}
        ]
    },

    // Global CSS: https://go.nuxtjs.dev/config-css
    css: [
        "@near-wallet-selector/modal-ui/styles.css"   ],

    // Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
    plugins: [],

    // Auto import components: https://go.nuxtjs.dev/config-components
    components: true,

    // Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
    buildModules: [],

    // Modules: https://go.nuxtjs.dev/config-modules
    modules: [
        // https://go.nuxtjs.dev/bootstrap
        'bootstrap-vue/nuxt',
        '@nuxtjs/axios',
        "@nuxtjs/proxy"
    ],

    // Build Configuration: https://go.nuxtjs.dev/config-build
    build: {},

    generate: {
        dir: 'dist'
    },

    axios: {
        proxy: true // Can be also an object with default options
    },

//    publicRuntimeConfig: {
//        verifierAddress: process.env.VERIFIER_ADDRESS || 'http://localhost:8080/',
//        apiAddress: process.env.API_ADDRESS || 'http://localhost:8080/'
//    },

    proxy: {
        '/verifier-api/': "http://localhost:8080/",
        '/api/': "http://localhost:8080/",
        '/webjars/': "http://localhost:8080/"
    }
}
