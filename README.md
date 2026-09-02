# OpenGist 1.15.1 RCE PoC

Proof of concept for an authenticated remote code execution vulnerability in
[OpenGist](https://github.com/thomiceli/opengist) 1.15.1.

A user who can create and push to a gist can use symbolic links to escape a
temporary gist checkout. Toggling a Markdown checkbox then writes through the
links and replaces the repository's `pre-receive` hook, which executes during
the resulting Git push with the privileges of the OpenGist service account.

OpenGist 1.15.2 fixes the issue by rejecting symbolic links in pushed gists and
refusing to follow them when writing gist content. See
[PR #799](https://github.com/thomiceli/opengist/pull/799) and the
[v1.15.2 release notes](https://github.com/thomiceli/opengist/releases/tag/v1.15.2).

## Requirements

- OpenGist 1.15.1
- An account with a fresh, disposable gist
- Python 3
- Git
- Linux, macOS, or WSL with symbolic-link support
- A listener and a target-side `nc` implementation that supports `-e` for the
  included reverse-shell payload

## Usage

1. Replace `YOUR-IP-CHANGE-THIS` in `opengist_poc.py` with your listener IP. If
   needed, change port `443` in `EVIL_PAYLOAD` as well.

2. Start the listener:

   ```console
   nc -lvnp 443
   ```

3. Run the PoC with the full 32-character UUID of a gist owned by the account:

   ```console
   python3 opengist_poc.py \
     --target http://127.0.0.1:6157 \
     --username alice \
     --password 'password' \
     --gist 0123456789abcdef0123456789abcdef
   ```

The script logs in, clones the gist, pushes the symlink chain, and sends the
authenticated checkbox request that triggers the vulnerable write. The gist
must not already contain `task.md` or the configured payload filename.

Run `python3 opengist_poc.py --help` for the complete CLI options.

## Mitigation

Upgrade to OpenGist 1.15.2 or later. On potentially affected systems, inspect
gist repositories for symbolic-link entries (Git mode `120000`), unexpected
hook changes, unusual child processes, and outbound connections.

## References

- [OpenGist v1.15.1](https://github.com/thomiceli/opengist/releases/tag/v1.15.1)
- [OpenGist v1.15.2](https://github.com/thomiceli/opengist/releases/tag/v1.15.2)
- [Symlink fix: PR #799](https://github.com/thomiceli/opengist/pull/799)

## License

[CC0 1.0 Universal](LICENSE)
