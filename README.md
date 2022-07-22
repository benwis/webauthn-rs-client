# webauthn-rs-client

## Description
This is a client for our implementation of a webauthn server, although it could be used for others.
It is written in Rust, compiled to WASM, and mean to be called in an event handler or similiar place.

It is closely tied to the example in the webauthn-rs repo, and we owe them a lot for doing such great
work on it.

It was tested with the Graphauth Webauthn server, and the Remix framework, although I can think of no
reason it wouldn't work in any other. The registration and login functions require access to the browser's
Credentials and window, so it probably won't run in node without a lot of finagling.

## Functions
```ts
export function process_registration(user_name: string, start_register_url: string, finish_register_url: string,tenant_name?: string): Promise<void>;
```
process_registration takes an user_name, two urls for the server endpoints, and an optional tenant_name. It is an async function that returns nothing. The urls should not have a trailing slash. Note this is a difference from the example webauthn-rs server, which is not designed
to be multi tenant.

```ts
export function process_login(user_name: string, start_login_url: string, finish_login_url: string, tenant_name?: string): Promise<string>;
```
process_login takes an user_name, two urls for the server endpoints, and an optional tenant_name. It is an async function that returns a random one-time authorization code as a string that can be handed to the server and used to get access and refresh tokens.

