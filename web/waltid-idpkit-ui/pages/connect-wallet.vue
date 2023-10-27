<template>
    <div class="d-flex justify-content-center text-white vh-100 vw-100">
        <div class="my-auto">
            <div class="text-white h1">walt.id IDP Kit</div>
            <div class="text-center">
                <button class="btn btn-success" @click="web3modal">
                    Connect wallet
                </button>
            </div>
            <div class="text-center">
                <br />
                <button class="btn btn-success" @click="beaconTezosWallet">
                    Connect wallet(Tezos)
                </button>
            </div>
            <div class="text-center">
                <br />
                <button class="btn btn-success" @click="nearWallet">
                    Connect wallet(Near)
                </button>
            </div>
            <div class="text-center">
                <br />
                <button class="btn btn-success" @click="PolkadotEVMWallet">
                    Connect wallet(Polkadot EVM)
                </button>
            </div>
            <div class="text-center">
                <br />
                <button class="btn btn-success" @click="flowWallet">
                    Connect wallet(Flow)
                </button>
            </div>
            <div class="text-center">
                <br />
                <button class="btn btn-success" @click="peraConnect">
                    Connect wallet(Algorand)
                </button>
            </div>
        </div>
    </div>
</template>

<script>
import Web3Modal from "web3modal";
import WalletConnectProvider from "@walletconnect/web3-provider";
import { ethers } from "ethers";
import { BeaconWallet } from "@taquito/beacon-wallet";
import { char2Bytes } from "@taquito/utils";
import { SigningType, signMessage } from "@airgap/beacon-sdk";
import { verifySignature } from "@taquito/utils";
import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";

import { setupWelldoneWallet } from "@near-wallet-selector/welldone-wallet";
import MyAlgoConnect  from "@randlabs/myalgo-connect";

import { setupDefaultWallets } from "@near-wallet-selector/default-wallets";
import {
    Near,
    KeyPair,
    utils,
    connect,
    keyStores,
    WalletConnection,
    InMemorySigner,
    Signer,
} from "near-api-js";
import * as buffer from "buffer";
import {PeraWalletConnect} from "@perawallet/connect";
import {
    web3Accounts,
    web3Enable,
    web3FromSource,
} from "@polkadot/extension-dapp";
import { stringToHex } from "@polkadot/util";
import { send as httpSend } from "@onflow/transport-http";
import * as fcl from "@onflow/fcl"

// config flow connect screen
fcl.config()
    .put("app.detail.title", "Walt.id Sign In Solution")
    .put("app.detail.icon", "https://images.squarespace-cdn.com/content/v1/609c0ddf94bcc0278a7cbdb4/4d493ccf-c893-4882-925f-fda3256c38f4/Walt.id_Logo_transparent.png?format=1500w")
// config flow to use HTTP
fcl
    .config()
    .put("accessNode.api", "https://rest-testnet.onflow.org")
    .put("sdk.transport", httpSend)
// config discovery endpoint
fcl.config({
    // Testnet
    "discovery.wallet": "https://fcl-discovery.onflow.org/testnet/authn",
    // Mainnet
    // "discovery.wallet": "https://fcl-discovery.onflow.org/authn",
})

const providerOptions = {
    walletconnect: {
        package: WalletConnectProvider, // required
        options: {
            rpc: {
                4: "https://rinkeby.infura.io/v3/",
            },
            chainId: 4,
        },
    },
};

const wallet = new BeaconWallet({ name: "Walt.id" });

export default {
    name: "ConnectWallet",
    data() {
        return {
            eth_account: null,
        };
    },
    methods: {
        async web3modal() {
            const web3Modal = new Web3Modal({
                cacheProvider: false, // optional
                providerOptions, // required
            });
            const instance = await web3Modal.connect();
            const provider = new ethers.providers.Web3Provider(instance);

            try {
                const redirect_uri = this.$route.query["redirect_uri"];
                const session_id = this.$route.query["session"];
                const nonce = this.$route.query["nonce"];

                const signer = provider.getSigner();
                const signerAddress = await signer.getAddress();

                const description = "Sign in with Ethereum to the app.";
                const origin = window.location.origin;
                const domain = window.location.host;

                const eip4361msg = `${domain} wants you to sign in with your Ethereum account:
                ${signerAddress}
                ${description}
                URI: ${origin}
                Version: 1
                Chain ID: 1
                Nonce: ${nonce}`;

                let msgSignature;
                try {
                    msgSignature = await signer.signMessage(eip4361msg);
                } catch (ex) {
                    this.catchSigningError(ex);
                    return false;
                }
                // callback to IDP Kit with ethereum address
                window.location = `${redirect_uri}?session=${session_id}&ecosystem=EVM&message=${encodeURIComponent(
                    eip4361msg
                )}&signature=${msgSignature}`;
            } catch (e) {
                console.log(e.response.data);
                this.error = true;
                this.errorMessage = e.response.data.title;
            }
        },
        async beaconTezosWallet() {
            try {
                const redirect_uri = this.$route.query["redirect_uri"];
                const session_id = this.$route.query["session"];
                const nonce = this.$route.query["nonce"];
                const permissions = await wallet.client.requestPermissions();
                this.tezos_account = permissions.address;
                const origin = window.location.origin;
                const domain = window.location.host;
                const ISO8601formatedTimestamp = new Date().toISOString();
                const description = "Sign in with Tezos to the app.";
                const message = `${domain} wants you to sign in with your Tezos account: ${permissions.address}. Public Key: ${permissions.publicKey}.Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;

                // The bytes to sign
                const bytes = char2Bytes(message);
                const payloadBytes =
                    "05" + "0100" + char2Bytes(bytes.length.toString()) + bytes;

                // The payload to send to the wallet
                const payload = {
                    signingType: SigningType.MICHELINE,
                    payload: payloadBytes,
                    sourceAddress: this.tezos_account,
                };
                // The signing
                const signedPayload = await wallet.client.requestSignPayload(
                    payload
                );
                // The signature
                const { signature } = signedPayload;
                window.location = `${redirect_uri}?session=${session_id}&ecosystem=Tezos&message=${message}&signature=${signature}`;
            } catch (error) {
                console.log("Got error:", error);
            }
        },
        async nearWallet() {

            try {
                const selector = await setupWalletSelector({
                    network: "testnet",
                    modules: [
                        ...(await setupDefaultWallets()),

                        setupWelldoneWallet(),
                    ],
                });

                const redirect_uri = this.$route.query["redirect_uri"];
                const session_id = this.$route.query["session"];
                const nonce = this.$route.query["nonce"];
                const origin = window.location.origin;
                const domain = window.location.host;
                const ISO8601formatedTimestamp = new Date().toISOString();
                const description = "Sign in with Near to the app.";

                const modal = setupModal(selector, {
                    title: "Select a wallet",
                    description: "Select a wallet to connect to this dApp",
                });
                modal.show();

                const wallet = await selector.wallet("welldone-wallet");

                const accounts = await wallet.getAccounts();
                console.log("accounts", accounts[0].accountId);

                const message = `${domain} wants you to sign in with your Near account:${accounts[0].accountId} . Public Key: ${accounts[0].publicKey} .Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;

                const verify = await wallet.verifyOwner({
                    message: message,
                });

                const signature = verify.signature;
                console.log("signature", signature);

                //use url encoder for signature

                const urlSignature = encodeURIComponent(signature);

                window.location = `${redirect_uri}?session=${session_id}&ecosystem=NEAR&message=${message}&signature=${urlSignature}`;
            } catch (error) {
                console.log("Got error:", error);
            }
        },
        async PolkadotEVMWallet() {
            const redirect_uri = this.$route.query["redirect_uri"];
            const session_id = this.$route.query["session"];
            const nonce = this.$route.query["nonce"];
            const origin = window.location.origin;
            const domain = window.location.host;
            const ISO8601formatedTimestamp = new Date().toISOString();
            const description = "Sign in with Polkadot to the app.";

            // Request permission to access accounts
            const extensions = await web3Enable("Walt.id IDP Kit");
            if (extensions.length === 0) {
                // No extension installed, or the user did not accept the authorization
                return;
            }
            // Get all the accounts
            const allAccounts = await web3Accounts();
            if (allAccounts.length === 0) {
                // No account has been found
                return;
            }
            // Use the first account
            const account = allAccounts[0];
            console.log("account", account);
            const injector = await web3FromSource(account.meta.source);
            const signRaw = injector?.signer?.signRaw;
            const message = `${domain} wants you to sign in with your Polkadot account:${account.meta.name} . Public Key: ${account.address} .Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;

            if (!!signRaw) {
                // after making sure that signRaw is defined
                // we can use it to sign our message
                const  signature = await signRaw({
                    address: account.address,
                    data: stringToHex(message),
                    type: "bytes",
                });

                const urlSignature = encodeURIComponent(signature.signature);

                const urlMessage = encodeURIComponent(message);


              let url = `${redirect_uri}?session=${session_id}&ecosystem=Polkadot&message=${urlMessage}&signature=${urlSignature}`;

            window.location = url;
            }
        },
        async flowWallet(){
            const redirect_uri = this.$route.query["redirect_uri"];
            const session_id = this.$route.query["session"];
            const nonce = this.$route.query["nonce"];
            const origin = window.location.origin;
            const domain = window.location.host;
            const ISO8601formatedTimestamp = new Date().toISOString();
            const description = "Sign in with Flow to the app.";

                fcl.currentUser.subscribe(async (currentUser) => {

                    fcl.config().put('flow.network', 'testnet');
                const message = `${domain} wants you to sign in with your Flow account:${currentUser.addr} . Public Key: ${currentUser.cid} .Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;
                console.log("The Current User", currentUser);
                console.log("The message",message);


                         const MSG = Buffer.from(message).toString("hex")
                         const signature =await fcl.currentUser.signUserMessage(MSG)
                        console.log("The signature",signature);

                            const urlSignature = encodeURIComponent(JSON.stringify(signature))

                            console.log("The urlSignature",urlSignature);

                            const urlMessage = encodeURIComponent(message);
                            let url = `${redirect_uri}?session=${session_id}&ecosystem=Flow&message=${urlMessage}&signature=${urlSignature}`;
                            console.log("The url",url)
                           window.location = url;





                })


        },
        async AlgorandWallet(){


            const redirect_uri = this.$route.query["redirect_uri"];
            const session_id = this.$route.query["session"];
            const nonce = this.$route.query["nonce"];
            const origin = window.location.origin;
            const domain = window.location.host;
            const ISO8601formatedTimestamp = new Date().toISOString();
            const description = "Sign in with Flow to the app.";


            const settings = {
                shouldSelectOneAccount: true,
            };


            const myAlgoWallet = new MyAlgoConnect();
            console.log("logging in")
//   try {
            const accounts = await myAlgoWallet.connect(settings);
            const account = accounts[0]
            const message = `${domain} wants you to sign in with your Algorand account:${account.name} . Public Key: ${account.address} .Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;


            const textEncoder = new TextEncoder();
            const encodedMessage = textEncoder.encode(message);

            const data = new Uint8Array([...encodedMessage]);

            const signature = await myAlgoWallet.signBytes(data, account.address);

            console.log("signature",signature);

            const urlSignature = encodeURIComponent(JSON.stringify(signature))

            const urlMessage = encodeURIComponent(message);
            let url = `${redirect_uri}?session=${session_id}&ecosystem=Algorand&message=${urlMessage}&signature=${signature}`;

            window.location = url;

        },
        async peraConnect (){


            const redirect_uri = this.$route.query["redirect_uri"];
            const session_id = this.$route.query["session"];
            const nonce = this.$route.query["nonce"];
            const origin = window.location.origin;
            const domain = window.location.host;
            const ISO8601formatedTimestamp = new Date().toISOString();
            const description = "Sign in with Algorand to the app.";


            const peraWallet = new PeraWalletConnect({
                chainId: 416002,
                shouldShowSignTxnToast: false
            });
            peraWallet
                .connect()
                .then(async (newAccounts) => {
                    // Setup the disconnect event listener
                    peraWallet.connector?.on("disconnect", () => {
                        console.log("disconnected");
                        peraWallet.disconnect();

                    });
                    let account = newAccounts[0];
                    console.log("account", account);
                    const message = `${domain} wants you to sign in with your Algorand account:${account} . Public Key: ${account} .Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`;
                    const textEncoder = new TextEncoder();
                    const encodedMessage = textEncoder.encode(message);

                    const signedData = await peraWallet.signData([
                        {
                            data: new Uint8Array(Buffer.from(encodedMessage)),
                            message: "Message confirmation"
                        },
                        {
                            data: new Uint8Array(Buffer.from(`agent//${navigator.userAgent}`)),
                            message: "User agent confirmation"
                        }
                    ], account);

                    const urlMessage = encodeURIComponent(message);
                    let url = `${redirect_uri}?session=${session_id}&ecosystem=Algorand&message=${urlMessage}&signature=${signedData[0]}`;

                    window.location = url;

                }).catch((error) => {
                    console.log("error", error);
                });


        }
    },
};
</script>

<style>
.menu-link {
    color: white;
}
</style>
