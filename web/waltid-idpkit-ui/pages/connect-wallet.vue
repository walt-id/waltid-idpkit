<template>
  <div class="d-flex justify-content-center text-white vh-100 vw-100">
    <div class="my-auto">
      <div class="text-white h1">walt.id IDP Kit</div>
      <div class="text-center">
        <button class="btn btn-success" @click="web3modal">Connect wallet</button>
      </div>
    </div>
  </div>
</template>

<script>
import Web3Modal from "web3modal";
import WalletConnectProvider from "@walletconnect/web3-provider";
import {ethers} from 'ethers';


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
        window.location = `${redirect_uri}?session=${session_id}&message=${encodeURIComponent(eip4361msg)}&signature=${msgSignature}`
      } catch (e) {
        console.log(e.response.data)
        this.error = true
        this.errorMessage = e.response.data.title
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
