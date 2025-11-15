# edgegrid

This tool provides a convenient way to sign and send requests to the Akamai API using the EdgeGrid authentication scheme. It offers two subcommands: `curl`, which signs and sends a single HTTP request, and `proxy`, which starts a reverse proxy that automatically signs and forwards requests to the Akamai API.

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

- `--host` (`EDGEGRID_HOST`): Your Akamai API host.
- `--client-token` (`EDGEGRID_CLIENT_TOKEN`): Your client token.
- `--client-secret` (`EDGEGRID_CLIENT_SECRET`): Your client secret.
- `--access-token` (`EDGEGRID_ACCESS_TOKEN`): Your access token.
- `--key` (`EDGEGRID_ACCOUNT_KEY`): Your account switch key (optional).

## Usage

### `curl`

The `curl` subcommand allows you to sign and send a single HTTP request to the Akamai API. It supports a subset of the standard `curl` flags, including:

- `--url`: The URL for the API request. This is optional if the URL is provided as a positional argument.
- `-X`, `--request`: The HTTP method for the request (e.g., `GET`, `POST`).
- `-H`, `--header`: An HTTP header to include in the request. Can be specified multiple times.
- `-d`, `--data`: The data to send in the request body.
- `-b`, `--cookie`: A cookie to send with the request.

Here's an example of how to use the `curl` subcommand to send a `GET` request:

```bash
edgegrid curl "/diagnostic-tools/v2/ghost-locations/available"
```

### `proxy`

The `proxy` subcommand starts a reverse proxy that automatically signs incoming requests and forwards them to the Akamai API. This is useful for developing and testing applications that interact with the Akamai API.

The following flags are available for the `proxy` subcommand:

- `-a`, `--addr`: The address for the proxy server to listen on.
- `--tls-crt`: The path to the TLS/SSL certificate file for the proxy.
- `--tls-key`: The path to the TLS/SSL key file for the proxy.

Here's an example of how to start the proxy server:

```bash
edgegrid proxy -a "127.0.0.1:8080"
```

Once the proxy is running, you can send requests to it as if you were sending them directly to the Akamai API. The proxy will automatically sign the requests and forward them to the API.
