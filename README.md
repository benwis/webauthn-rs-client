# webauthn-rs-client

## Description
This is a client for our implementation of a webauthn server, although it could be used for others.
It is written in Rust, compiled to WASM, and mean to be called in an event handler or similiar place.

It was tested with the Graphauth Webauthn server, and the Remix framework, although I can think of no
reason it wouldn't work in any other. The registration and login functions require access to the browser's
Credentials and window, so it probably won't run in node without a lot of finagling.

## Functions
```ts
export function process_registration(tenant_name: string, user_name: string, start_register_url: string, finish_register_url: string): Promise<void>;
```
process_registration takes a tenant_name, user_name, and two urls for the server endpoints. It is an async function that returns nothing. The urls should not have a trailing slash. Note this is a difference from the example webauthn-rs server, which is not designed
to be multi tenant.

```ts
export function process_login(tenant_name: string, user_name: string, start_login_url: string, finish_login_url: string): Promise<string>;
```
process_login takes a tenant_name, user_name, and two urls for the server endpoints. It is an async function that returns a random one-time authorization code as a string that can be handed to the server and used to get access and refresh tokens.

