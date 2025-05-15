import type { OAuthProviderTokenMap, OAuthProvider } from "./src/types";

declare module "h3" {
  interface H3EventContext {
    h3OAuthKit?: {
      [P in OAuthProvider]?: OAuthProviderTokenMap[P];
    };
  }
}
