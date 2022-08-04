<template>
  <div class="d-flex justify-content-center text-white vh-100 vw-100">
    <div class="fixed-top">
      <div class="text-right px-3 py-3">
        <a href="/api/swagger" class="menu-link" target="_blank">Swagger</a> |
        <a href="https://docs.walt.id/v/idpkit/getting-started/quick-start" class="menu-link" target="_blank">Documentation</a> |
        <a href="https://github.com/walt-id/waltid-idpkit" class="menu-link" target="_blank">GitHub</a>
      </div>
    </div>
    <div class="my-auto">
      <div class="text-white h1">walt.id IDP Kit</div>
      <div class="text-center">
        <a class="btn btn-info" href="https://docs.walt.id/v/idpkit/getting-started/quick-start" target="_blank">Get Started</a>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'IndexPage'
}
</script>

<style>
.menu-link {
  color: white;
}
</style>
