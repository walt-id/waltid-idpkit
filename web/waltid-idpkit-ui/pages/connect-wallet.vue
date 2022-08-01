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
      const provider = await web3Modal.connect()
      console.log("provider", provider)
      if(provider.isMetaMask) {
        this.eth_account = provider.selectedAddress
      } else {
        this.eth_account = provider.accounts[0]
        provider.disconnect()
      }

      try {
        const redirect_uri = this.$route.query["redirect_uri"]
        const session_id = this.$route.query["session"]
        // TODO: SIWE challenge!?!


        // callback to IDP Kit with ethereum address
        window.location = `${redirect_uri}?sessionId=${session_id}&account=${this.eth_account}`
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
