import { H3Event, H3EventContext, EventHandler } from 'h3';

type OAuthProvider = "azure" | "clio" | "intuit";
type RequiredPick<T, K extends keyof T> = {
    [P in K]-?: NonNullable<T[P]>;
};
interface OAuthProviderConfig {
    clientId: string;
    clientSecret: string;
    authorizeEndpoint: string;
    tokenEndpoint: string;
    redirectUri: string;
    scopes: string[];
}

declare function defineProtectedRoute<Providers extends OAuthProvider[]>(providers: [...Providers], handler: (event: H3Event & {
    context: RequiredPick<H3EventContext, `${Providers[number]}AccessToken`>;
}) => unknown): (event: H3Event) => unknown;

declare function defineOAuthProvider(provider: OAuthProvider, config: OAuthProviderConfig): void;
declare function getOAuthProviderConfig(provider: OAuthProvider): OAuthProviderConfig;

declare function handleOAuthLogin(provider: OAuthProvider, options?: {
    state?: string | ((event: H3Event) => string);
    mode?: "manual" | "redirect";
}): EventHandler;

declare function handleOAuthCallback(provider: OAuthProvider, options?: {
    redirectTo?: string;
}): EventHandler;

export { defineOAuthProvider, defineProtectedRoute, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin };
