# byke bridge

byke bridge lets byke's agents reach services inside your network (an internal API, a database, an MCP server, a mail
server) without opening anything to the internet. You run this small program inside your network. It connects **out**
to byke, and carries only the connections you allow, to the services you name.

## Run it

On byke's Bridges page, make a bridge, add its targets (each a name, host, port and protocol), then **Add a relay**. The
page shows a one-time token, valid for an hour, and the command to run, for example:

```sh
docker run -d --name byke-bridge --restart unless-stopped \
  -v byke-bridge:/var/lib/byke-bridge \
  -e BYKE_BRIDGE_TOKEN=bbe_… \
  -e BYKE_BRIDGE_ALLOW=erp.internal:8080,10.0.4.0/24:5432 \
  registry.gitlab.com/byke-project/com.byke.bridge:latest
```

The token is used once. After that, the relay keeps its own key and certificate in the volume and needs no token.

Run two or more relays for the same bridge, on different machines, so that one can be restarted while the other carries
the calls. Each needs its own token.

## What it may reach

`BYKE_BRIDGE_ALLOW` (or `--allow`) is the relay's own list. It refuses everything else, whatever byke asks:

| Entry | Allows |
|---|---|
| `erp.internal:8080` | that name and port |
| `*.corp.example:443` | any name under `corp.example`, port 443 |
| `10.0.4.0/24:5432` | any address in that network, port 5432 (a name is allowed when it resolves into it) |
| `192.168.1.9:*` | any port on that address |

byke checks its own list too, the targets registered on the Bridges page. A call needs both to agree.

## What it does, and what it sees

- **Out only.** It connects to `wss://bridge.byke.dev` on port 443. Nothing listens in your network. If your network
  goes out through a proxy, set `HTTPS_PROXY` and it uses it.
- **Who it is.** The first time, it makes an Ed25519 key, proves it holds the key, and spends the one-time token. byke
  signs a certificate for that key, valid for 7 days and renewed while the relay is connected. At every connection
  after that, it proves its key again by signing byke's challenge. This also works through a firewall that inspects
  TLS.
- **What it carries.** Bytes. A call to an `https://` service stays encrypted from byke to that service, so the relay
  sees only where it goes and how much. A call to an `http://` service passes through it as it is.
- **Its log.** Every connection, allowed or refused, is written to its log as one JSON line: the call's id, the
  target, the address, the bytes each way, how long it took and how it ended. Set `BYKE_BRIDGE_LOG_FILE` to keep a copy
  in a file. byke keeps the same record on its side, on the bridge's page.
- **Turning it off.** Revoke the relay on the Bridges page: byke ends its session within seconds, and it exits (code 3)
  until it is enrolled again with a new token. Or simply stop the container.

## Settings

| Variable | Flag | Default |
|---|---|---|
| `BYKE_BRIDGE_TOKEN` | `--token` | the one-time token (first start only) |
| `BYKE_BRIDGE_ALLOW` | `--allow` | empty: it refuses everything |
| `BYKE_BRIDGE_SERVER` | `--server` | `wss://bridge.byke.dev/v1/relay` |
| `BYKE_BRIDGE_STATE` | `--state` | `/var/lib/byke-bridge` |
| `BYKE_BRIDGE_LOG_FILE` | `--log-file` | none |
| `HTTPS_PROXY`, `NO_PROXY` | | your outbound proxy, if any |

## Build it yourself

```sh
go build ./cmd/byke-bridge        # or: docker build -t byke-bridge .
go test -race ./...
```

`protocol/` is the whole wire protocol between the relay and byke's gateway.
