<template>
  <div class="background">
    <Nuxt />
  </div>
</template>

<script>

export default {
  name: 'default',
  data() {
    return {

    }
  },
  computed: {

  },
  watch: {

  },
  methods:{

  }
};
</script>

<style>
.background {
  background: black url("static/1.png") no-repeat bottom left;
  background-size: 100vh;
  width: 100vw;
  height: 100vh;
  position: fixed;
}
</style>
