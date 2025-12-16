## [1.2.2](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.2.1...v1.2.2) (2025-12-16)


### Bug Fixes

* enable tokoen refresh when access_token cookie is missing ([5dedb72](https://github.com/sashamilenkovic/h3-oauth-kit/commit/5dedb7201071a5626106491f45ebe721cf0e3ee7))

## [1.2.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.2.0...v1.2.1) (2025-12-06)


### Bug Fixes

* run instance discovery before config lookup in defineProtectedRoute ([d68d101](https://github.com/sashamilenkovic/h3-oauth-kit/commit/d68d1017273f768883f5216fe41e403ca7ae263e))

# [1.2.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.1.3...v1.2.0) (2025-11-03)


### Features

* add JWT validation with signature verification and JWKS caching ([fb61dce](https://github.com/sashamilenkovic/h3-oauth-kit/commit/fb61dceceb53c7ac96d98be53f733a582f13c5fa))

## [1.1.3](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.1.2...v1.1.3) (2025-11-03)


### Bug Fixes

* disable codecov search to prevent uploading stale pnpm-store coverage ([ea326a3](https://github.com/sashamilenkovic/h3-oauth-kit/commit/ea326a335219b69c7afc67271b3174eb2635bde8))

## [1.1.2](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.1.1...v1.1.2) (2025-11-03)


### Bug Fixes

* explicitly specify coverage file path for codecov ([1fcca28](https://github.com/sashamilenkovic/h3-oauth-kit/commit/1fcca285fc281ed1b0161d16a2bc6282d5edd83b))

## [1.1.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.1.0...v1.1.1) (2025-11-03)


### Bug Fixes

* use correct coverage script in CI workflow ([b42e707](https://github.com/sashamilenkovic/h3-oauth-kit/commit/b42e70756105d43b1ba76ad4793463b371dc1a56))

# [1.1.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v1.0.0...v1.1.0) (2025-11-03)


### Features

* add tree-shakable token introspection and device flow ([c8bde5f](https://github.com/sashamilenkovic/h3-oauth-kit/commit/c8bde5f7fb5af94f87fe3f2492177f5488a69e87))

# [1.0.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.13.1...v1.0.0) (2025-11-03)


### Features

* add OAuth 2.0 Client Credentials flow for M2M authentication ([6bd0f44](https://github.com/sashamilenkovic/h3-oauth-kit/commit/6bd0f4444908c963292504ff6021675cdea3179e))


### BREAKING CHANGES

* None - fully backward compatible

## [0.13.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.13.0...v0.13.1) (2025-11-03)


### Bug Fixes

* add public access to publishConfig for npm organization package ([e0c5379](https://github.com/sashamilenkovic/h3-oauth-kit/commit/e0c537922e5856a60bb464ac1bf90f271de789d1))

# [0.13.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.12.1...v0.13.0) (2025-11-03)


### Features

* add token prefetching, revocation, and status API ([f2f1c16](https://github.com/sashamilenkovic/h3-oauth-kit/commit/f2f1c167de99f826a58ffac14d8e74eb206d86d9))

## [0.12.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.12.0...v0.12.1) (2025-10-19)


### Bug Fixes

* make refresh tokens optional in oauth flow ([4fb63bf](https://github.com/sashamilenkovic/h3-oauth-kit/commit/4fb63bfb86b8bc441e814b2ac010d6d5a8e7d708))

# [0.12.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.11.0...v0.12.0) (2025-10-02)


### Features

* adds generics for providers ([28aa639](https://github.com/sashamilenkovic/h3-oauth-kit/commit/28aa639ee80e6d187a06ddc11302dead2b5f92d5))

# [0.11.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.10.0...v0.11.0) (2025-08-20)


### Features

* adds opencase as provider option ([bf14a64](https://github.com/sashamilenkovic/h3-oauth-kit/commit/bf14a64f8973c4b413d2412722190fdfe7201621))

# [0.10.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.9.1...v0.10.0) (2025-06-23)


### Features

* add h3OauthKitInstances context ([acd0c70](https://github.com/sashamilenkovic/h3-oauth-kit/commit/acd0c70197dbd053fc5a62cf31924c45e74f9e95))

## [0.9.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.9.0...v0.9.1) (2025-06-20)


### Bug Fixes

* refresh flow bug where lack of access token prevented it ([e849f7e](https://github.com/sashamilenkovic/h3-oauth-kit/commit/e849f7e675e770ad9d87916946c15d9b207a6bf5))

# [0.9.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.8.0...v0.9.0) (2025-06-16)


### Features

* wraps registerOAuthProvider in composable to set encryption key, as opposed to referencing it within module scope directly ([3842107](https://github.com/sashamilenkovic/h3-oauth-kit/commit/384210714f673e3567d6a0f7a8c6794fea45462f))

# [0.8.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.7.0...v0.8.0) (2025-06-13)


### Features

* swaps out node crypto approach for web api supported one ([a0dc401](https://github.com/sashamilenkovic/h3-oauth-kit/commit/a0dc401a9ac99e3613f964ce71f98a5f15edbed0))

# [0.7.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.6.0...v0.7.0) (2025-05-27)


### Features

* remove resolveInstance option in favor of withInstanceKeys helper ([e92b725](https://github.com/sashamilenkovic/h3-oauth-kit/commit/e92b725ea17ad05a42f9bb204d4731b1138aeb1a))

# [0.6.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.5.0...v0.6.0) (2025-05-27)


### Features

* implement multi-instance oauth with preserve mode and dynamic oauth key resolution ([c2131da](https://github.com/sashamilenkovic/h3-oauth-kit/commit/c2131da72b105efd12d0adf1f6f0cf5cec8d0095))

# [0.5.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.4.1...v0.5.0) (2025-05-27)


### Features

* adds utility function for checking if oauthprovider config exists ([db1c603](https://github.com/sashamilenkovic/h3-oauth-kit/commit/db1c6036481f6463543625cf3360b91dd3575d8c))

## [0.4.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.4.0...v0.4.1) (2025-05-26)


### Bug Fixes

* fixes issue where provider key was used in place of instance key when setting provider cookies ([ac07ade](https://github.com/sashamilenkovic/h3-oauth-kit/commit/ac07ade9bb366f9e019616a546217f42c4ffba6a))

# [0.4.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.3.0...v0.4.0) (2025-05-26)


### Features

* adds multi-tenant support ([275bc3c](https://github.com/sashamilenkovic/h3-oauth-kit/commit/275bc3c28e7c2f6db3d83b382727d0bcf6d114d8))

# [0.3.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.2.0...v0.3.0) (2025-05-21)


### Features

* encrypt refresh tokens before setting cookies ([6eb1304](https://github.com/sashamilenkovic/h3-oauth-kit/commit/6eb13041bb39d0e84b6d865ffa9ca4654e0aaeed))

# [0.2.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.1.1...v0.2.0) (2025-05-20)


### Features

* allow dynamic provider logout via query params ([f1a23ad](https://github.com/sashamilenkovic/h3-oauth-kit/commit/f1a23ad6ff10278814f00f4c2588323159fb4edb))

## [0.1.1](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.1.0...v0.1.1) (2025-05-16)


### Bug Fixes

* trigger release ([bd3f260](https://github.com/sashamilenkovic/h3-oauth-kit/commit/bd3f26089cba3bf5b3fce1e715288662c6129943))

# [0.1.0](https://github.com/sashamilenkovic/h3-oauth-kit/compare/v0.0.2...v0.1.0) (2025-05-16)


### Features

* adds utility function to delete provider cookies, adds github workflow ([7ef908c](https://github.com/sashamilenkovic/h3-oauth-kit/commit/7ef908c4e7002d667513ec1981fe4e602026753d))
