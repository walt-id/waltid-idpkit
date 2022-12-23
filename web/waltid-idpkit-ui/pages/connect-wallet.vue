<template>
  <div class="d-flex justify-content-center text-white vh-100 vw-100">
    <div class="my-auto">
      <div class="text-white h1">walt.id IDP Kit</div>
      <div class="text-center">
        <button class="btn btn-success" @click="web3modal">Connect wallet</button>
      </div>
      <div class="text-center">
        <br/>
        <button class="btn btn-success" @click="beaconTezosWallet">Connect wallet(Tezos)</button>
      </div>
    </div>
  </div>
</template>

<script>
import Web3Modal from "web3modal";
import WalletConnectProvider from "@walletconnect/web3-provider";
import {ethers} from 'ethers';
import { BeaconWallet } from "@taquito/beacon-wallet";
import { char2Bytes } from '@taquito/utils';
import { SigningType } from '@airgap/beacon-sdk';
import {verifySignature} from "@taquito/utils";





const providerOptions = {
  walletconnect: {
    package: WalletConnectProvider, // required
    options: {
      rpc: {
        4: "https://rinkeby.infura.io/v3/"
      },
      chainId: 4
    }
  }
};

const wallet = new BeaconWallet({ name: "Walt.id" });


export default {
  name: 'ConnectWallet',
  data() {
    return {
      eth_account: null
    }
  },
  methods: {
    async web3modal () {
      const web3Modal = new Web3Modal({
        cacheProvider: false, // optional
        providerOptions // required
      });
      const instance = await web3Modal.connect()
      const provider = new ethers.providers.Web3Provider(instance);

      try {
        const redirect_uri = this.$route.query["redirect_uri"]
        const session_id = this.$route.query["session"]
        const nonce= this.$route.query["nonce"]

        const signer = provider.getSigner();
        const signerAddress = await signer.getAddress();

        const description = 'Sign in with Ethereum to the app.';
        const origin = window.location.origin;
        const domain = window.location.host;

        const eip4361msg = `${domain} wants you to sign in with your Ethereum account:
${signerAddress}
${description}
URI: ${origin}
Version: 1
Chain ID: 1
Nonce: ${nonce}`

      let msgSignature
      try {
        msgSignature = await signer.signMessage(eip4361msg);
      } catch (ex) {
        this.catchSigningError(ex)
        return false
      }
        // callback to IDP Kit with ethereum address
        window.location = `${redirect_uri}?session=${session_id}&chain=EVM&message=${encodeURIComponent(eip4361msg)}&signature=${msgSignature}`
      } catch (e) {
        console.log(e.response.data)
        this.error = true
        this.errorMessage = e.response.data.title
      }
    },
       async beaconTezosWallet(){
      try {
        const redirect_uri = this.$route.query["redirect_uri"]
        const session_id = this.$route.query["session"]
        const nonce= this.$route.query["nonce"]
        const permissions = await wallet.client.requestPermissions();
        this.tezos_account= permissions.address
        const origin = window.location.origin;
        const domain = window.location.host;
        const ISO8601formatedTimestamp = new Date().toISOString();
        const description = 'Sign in with Tezos to the app.';
        const message = `${domain} wants you to sign in with your Tezos account: ${permissions.address}. Public Key: ${permissions.publicKey}.Date: ${ISO8601formatedTimestamp}. ${description} URI: ${origin}. Version: 1. Nonce: ${nonce}`


        // The bytes to sign
        const bytes = char2Bytes(message);
        const payloadBytes = '05' + '0100' + char2Bytes(bytes.length.toString()) + bytes;

        // The payload to send to the wallet
        const payload = {
          signingType: SigningType.MICHELINE,
          payload: payloadBytes,
          sourceAddress: this.tezos_account,
        };
        // The signing
        const signedPayload = await wallet.client.requestSignPayload(payload);
        // The signature
        const { signature } = signedPayload;
        window.location = `${redirect_uri}?session=${session_id}&chain=Tezos&message=${message}&signature=${signature}`
      } catch (error) {
        console.log("Got error:", error);
      }
    },
  }
}
</script>

<style>
.menu-link {
  color: white;
}
</style>
