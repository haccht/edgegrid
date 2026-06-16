# edgegrid

`edgegrid` is a command-line tool for signing requests to the Akamai API with the EdgeGrid authentication scheme.

It provides two subcommands:

- `curl`: signs and sends a single HTTP request.
- `proxy`: starts a reverse proxy that signs incoming requests and forwards them to the Akamai API.


## Configuration

The tool can be configured using a `.edgerc` file, command-line flags, or environment variables. The `.edgerc` file is the recommended approach for storing your credentials. By default, the tool looks for this file at `~/.edgerc`.

Here's an example of what a `.edgerc` file looks like:

```
[default]
host = your-api-host.luna.akamaiapis.net
client_token = your_client_token
client_secret = your_client_secret
access_token = your_access_token
```

You can also provide your credentials using the following command-line flags or their corresponding environment variables:

- `--host` (`EDGEGRID_HOST`): The API host.
- `--client-token` (`EDGEGRID_CLIENT_TOKEN`): The client token for authentication.
- `--client-secret` (`EDGEGRID_CLIENT_SECRET`): The client secret for authentication.
- `--access-token` (`EDGEGRID_ACCESS_TOKEN`): The access token for authentication.
- `--key` (`EDGEGRID_ACCOUNT_KEY`): Account switch key for authorization.

## Usage

The top-level help shows the global EdgeGrid configuration flags:

```text
Usage of edgegrid:
      --access-token string    The access token for authentication. (env: EDGEGRID_ACCESS_TOKEN)
      --client-secret string   The client secret for authentication. (env: EDGEGRID_CLIENT_SECRET)
      --client-token string    The client token for authentication. (env: EDGEGRID_CLIENT_TOKEN)
  -r, --file string            Path to the .edgerc file. (default "~/.edgerc")
      --host string            The API host. (env: EDGEGRID_HOST)
  -k, --key string             Account switch key for authorization. (env: EDGEGRID_ACCOUNT_KEY)
  -s, --section string         The section of the .edgerc file to use. (default "default")
```

### `curl`

The `curl` subcommand signs and sends a single HTTP request to the Akamai API.

It normally works as a wrapper around the standard `curl` command.
When `curl` is installed, `edgegrid curl` preserves the curl-style arguments, replaces the target endpoint with the signed Akamai API URL, adds the EdgeGrid `Authorization` header, and then executes `curl`.

If the `curl` executable is not available, `edgegrid curl` falls back to Go's `net/http` client. In that mode, it still supports a practical subset of curl-style options listed below for signed Akamai API requests.

- `--url`: The URL or endpoint path for the request.
- `-X`, `--request`: The HTTP method to use.
- `-H`, `--header`: An HTTP header to include in the request.
- `-d`, `--data`: The data to send in the request body. To send data from a file, use the `@` prefix followed by the file path (e.g., `-d @request.json`).
- `--data-ascii`: The data to send in the request body. This behaves like `--data`.
- `--data-raw`: The data to send in the request body without special `@` handling.
- `--data-binary`: The binary data to send in the request body. File data read with `@` keeps newlines and carriage returns.

Here's an example of how to send a `POST` request with a JSON body from a file named `request.json`:

```bash
edgegrid curl -X POST -d @request.json "/some/api/endpoint"
```

### `proxy`

The `proxy` subcommand starts a reverse proxy that automatically signs incoming requests and forwards them to the Akamai API.

The following flags are available for the `proxy` subcommand:

- `-a`, `--addr`: The address for the proxy server to listen on.
- `--tls-crt`: The path to the TLS/SSL certificate file for the proxy.
- `--tls-key`: The path to the TLS/SSL key file for the proxy.

Here's an example of how to start the proxy server:

```bash
edgegrid proxy -a "127.0.0.1:8080"
```

Once the proxy is running, you can send requests to it as if you were sending them directly to the Akamai API. The proxy will automatically sign the requests and forward them to the API.
