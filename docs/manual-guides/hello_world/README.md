# Hello-world transport guides

Three first-run pages for Community 0.4.0. Each one is numbered. Each step says whether to type it in Terminal (Linux or macOS) or in Command Prompt (Windows), and the page shows the words you should see after the command. You paste a few small programs. You do not need to know Python.

Do [stdio-to-proxy-to-stdio.md](stdio-to-proxy-to-stdio.md) first. It installs the package from PyPI, runs `init`, writes a JSON config, makes one allowed tool call and one blocked tool call, reads the JSONL log, and runs verify. Do [stdio-to-proxy-to-https.md](stdio-to-proxy-to-https.md) when the tool server is an `https://` address. Do [https-gateway.md](https-gateway.md) when the client calls an HTTPS base URL and the proxy should audit that call.

The pictures under [images/](images/) are photographs of a Linux terminal from those runs. On Windows the words are the same. The prompt ends with `>` instead of `$`.

The matrix below is the smallest set of pages that still covers every transport this package implements.

## What the code accepts

The client on the first two pages is stdio. `mcp-glp-audit-proxy --help` lists `--config` and nothing else. A socket is opened only when the config contains a listen object. Those two pages do not set one. [https-gateway.md](https-gateway.md) does. There is no plaintext listener, no SSE listener, and no streamable-HTTP listener. See [the manual introduction](../README.md).

The target side (the MCP server the proxy calls) is one of two `upstreams[].transport` values:

| Transport | Direction | In the code |
|---|---|---|
| stdio | client to the proxy | the server process |
| stdio | proxy to the target | a child process (`command` and `args`) |
| https | proxy to the target | one JSON-RPC POST, TLS 1.3 only |

`https` sends `Accept: application/json, text/event-stream` and then reads the body as one JSON object. An SSE event stream is not parsed. `http://` is refused. Any other `transport` string is refused at config load.

Host products (Claude Desktop, Cursor, VS Code, and the Python agents) are all the stdio client. Their config files are in the other manuals. Do not copy those files here.

## Coverage matrix

| Guide | Client: stdio | Client: HTTPS | Target: stdio | Target: https |
|---|---|---|---|---|
| [stdio-to-proxy-to-stdio.md](stdio-to-proxy-to-stdio.md) | covered | | covered | |
| [stdio-to-proxy-to-https.md](stdio-to-proxy-to-https.md) | covered | | | covered |
| [https-gateway.md](https-gateway.md) | covered | covered | | covered |

Client SSE and a parsed SSE target are not in the matrix. This edition does not implement them. The HTTPS client is TLS 1.3 only.

Community keeps the audit trail in one JSONL file in a folder you choose. The config is a JSON file. Verify also writes a one-line `.head` sidecar next to the log. There is no database in these guides. SQL storage is available in Pro.

## Related manuals

- [QUICKSTART.md](../QUICKSTART.md) is the same audit from a git checkout, using `examples/`. A PyPI install does not include `examples/`.
- [generic-stdio.md](../generic-stdio.md) is the host `mcpServers` shape and a fuller proxy file.
- [python-sdk.md](../python-sdk.md) is the official SDK client. These walkthroughs use a short script instead.
- [anchoring-and-verification.md](../anchoring-and-verification.md) is `--print-head` and the off-host copy.
- [troubleshooting.md](../troubleshooting.md) is a denied call and fail-closed.
- [windows-lab-pc.md](../windows-lab-pc.md) is the Windows launcher. These pages use `py -3` in Command Prompt and `python3` in Terminal.
