# oauth-device

OAuth 2.0 device authorization flow for Rust desktop and CLI programs. No
redirect URI, no localhost listener, no client secret.

The device grant is the one OAuth flow a desktop app can complete with nothing
but a client id:

1. the app asks the provider for a short code,
2. the user types the code on the provider's page in any browser,
3. the app polls until a token appears.

```rust
use oauth_device::{provider, FileStore, Poll};

let github = provider("github").unwrap();
let device = oauth_device::request_device_code(github, &client_id)?;
println!("Open {} and enter {}", device.verification_uri, device.user_code);
loop {
    std::thread::sleep(std::time::Duration::from_secs(device.interval));
    match oauth_device::poll_token(github, &client_id, &device.device_code)? {
        Poll::Pending | Poll::SlowDown => continue,
        Poll::Token { token } => {
            let login = oauth_device::identity(github, &token)?;
            FileStore::new("connections.tsv").save(github.id, &token, &login)?;
            break;
        }
        Poll::Failure(message) => return Err(message),
    }
}
```

## What it handles

- `authorization_pending` and `slow_down` as distinct states, so callers back off
  instead of re-requesting.
- Expiry, denial and provider errors as one `Failure`, with the HTTP status kept
  in transport errors.
- Identity lookup after the token: GitHub `login`, Google `email`.
- A token file with owner-only permissions, keyed by provider.

## Presets

| provider | scope |
| --- | --- |
| `github` | `repo read:user` |
| `google` | `openid email` + calendar read |

`Provider` is a plain struct, so any provider that implements
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) works by filling in three URLs.

## Tests

`cargo test` runs the whole flow against a local HTTP server: the request bodies
the provider sees, the `pending → token` state machine, error mapping and the
file permissions.

## License

MIT.
