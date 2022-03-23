package id.walt.idp.rest

import id.walt.idp.oidc.OIDCController
import io.javalin.core.security.AccessManager
import io.javalin.core.security.RouteRole
import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.http.HttpCode

object IDPAccessManager : AccessManager {
  override fun manage(handler: Handler, ctx: Context, routeRoles: MutableSet<RouteRole>) {
    if(ctx.endpointHandlerPath().startsWith("/api/oidc/")) {
      if(OIDCController.accessControl(ctx, routeRoles)) {
        handler.handle(ctx)
      } else {
        ctx.status(HttpCode.UNAUTHORIZED).result("Unauthorized")
      }
    } else {
      handler.handle(ctx)
    }
  }
}
