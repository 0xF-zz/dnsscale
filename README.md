# DNSScale

DNSScale is a tool that automatically manages DNS records for your Tailscale network devices. It monitors your Tailscale network and creates DNS records in your chosen DNS provider, making it easy to access your devices by hostname.

## Features

- **Automatic DNS Management**: Creates and updates DNS records for Tailscale devices
- **Multiple DNS Providers**: Supports AWS Route53, Cloudflare, Pi-hole, and RFC 2136 with TSIG
- **Real-time Monitoring**: Polls Tailscale API for device changes and updates DNS accordingly
- **Tag-based Filtering**: Optionally manage only devices with specific tags
- **Ownership Tracking**: Creates TXT records to track which DNS records are managed by DNSScale
- **Structured Logging**: Comprehensive logging with configurable levels and formats
- **Flexible Configuration**: Support for configuration files, environment variables, and command-line flags

## Supported DNS Providers

### Cloudflare
- Uses Cloudflare API v4
- Requires API token with Zone:Read and DNS:Edit permissions
- Automatically disables proxy for Tailscale IP addresses

### AWS Route53
- Uses AWS SDK v2
- Supports AWS profiles and IAM roles
- Requires hosted zone ID

### RFC 2136
- Uses TCP dynamic DNS updates, with optional TSIG authentication
- Supports A, AAAA, and TXT records on compatible authoritative servers
- Requires AXFR permission for record listing and cleanup

## Installation

### Docker

```bash
docker build -t dnsscale .
docker run -d --name dnsscale --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,src="$(pwd)/dnsscale.yaml",dst=/app/dnsscale.yaml,readonly \
  dnsscale --config /app/dnsscale.yaml
```

The image runs as a non-root user; make the mounted configuration readable by
that user. No inbound ports or Tailscale daemon are needed: allow outbound HTTPS
to the Tailscale API and your provider, or TCP to the RFC 2136 server.
`docker stop dnsscale` sends SIGTERM for graceful shutdown.
Do not bake API tokens or TSIG secrets into the image.

For environment-only configuration, use `docker run --env-file /path/to/dnsscale.env dnsscale`.
The file uses `KEY=value` entries (not shell `export` statements), for example:

```dotenv
TAILSCALE_API_KEY=your-api-key
TAILSCALE_TAILNET=your-tailnet
DNS_PROVIDER=rfc2136
DNS_DOMAIN=example.com
RFC2136_SERVER=192.0.2.53:53
RFC2136_TSIG_KEY_NAME=dnsscale.
RFC2136_TSIG_SECRET=your-base64-secret
```

### From Source

```bash
git clone https://github.com/jaxxstorm/dnsscale
cd dnsscale
go build .
```

## Configuration

DNSScale can be configured using a configuration file, environment variables, or command-line flags.

### Configuration File (Recommended)

Create a configuration file named `dnsscale.yaml`:

```yaml
tailscale:
  api_key: "tskey-api-xxxxx"
  tailnet: "your-tailnet@gmail.com"

dns:
  provider: "cloudflare"
  domain: "example.com"
  zone_id: "your-zone-id"

  cloudflare:
    api_token: "your-cloudflare-api-token"

app:
  workers: 2
  poll_interval: "30s"
  required_tags:
    - "tag:production"

logging:
  level: "info"
  format: "console"
```

Run with configuration file:
```bash
./dnsscale --config dnsscale.yaml
```

### Environment Variables

```bash
export TAILSCALE_API_KEY="tskey-api-xxxxx"
export TAILSCALE_TAILNET="your-tailnet@gmail.com"
export DNS_ZONE_ID="your-zone-id"
export DNS_DOMAIN="example.com"
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"

./dnsscale --dns-provider cloudflare
```

### Command-line Flags

```bash
./dnsscale \
  --tailscale-api-key "tskey-api-xxxxx" \
  --tailscale-tailnet "your-tailnet@gmail.com" \
  --dns-provider cloudflare \
  --dns-domain example.com \
  --dns-zone-id your-zone-id \
  --cloudflare-api-token your-cloudflare-api-token \
  --log-level info
```

## Usage

### Generate Example Configuration

```bash
./dnsscale config example -o dnsscale.yaml
```

### Run with Configuration File

```bash
./dnsscale --config dnsscale.yaml
```

### Run with Environment Variables

```bash
./dnsscale --dns-provider cloudflare --log-level debug
```

## Configuration Options

### Tailscale Configuration

- `tailscale.api_key`: Tailscale API key (get from https://login.tailscale.com/admin/settings/keys)
- `tailscale.tailnet`: Your tailnet name (e.g., `example@gmail.com` or `example.ts.net`)

### DNS Configuration

- `dns.provider`: DNS provider (`route53`, `cloudflare`, `pihole`, or `rfc2136`); environment variable `DNS_PROVIDER`
- `dns.domain`: Domain to manage DNS records for
- `dns.zone_id`: DNS zone ID (required only for Route53 and Cloudflare)

#### Cloudflare Specific

- `dns.cloudflare.api_token`: Cloudflare API token with Zone:Read and DNS:Edit permissions

#### Route53 Specific

- `dns.route53.profile`: AWS profile to use (optional)
- `dns.route53.region`: AWS region (optional)

#### RFC 2136 (BIND, Knot DNS, PowerDNS, and other compatible servers)

```yaml
dns:
  provider: "rfc2136"
  domain: "nodes.example.com"
  rfc2136:
    server: "192.0.2.53:53" # Use [2001:db8::53]:53 for IPv6
    zone: "example.com" # Authoritative zone; defaults to dns.domain
    tsig_key_name: "dnsscale."
    tsig_secret: "YOUR_BASE64_ENCODED_SECRET"
    tsig_algorithm: "hmac-sha256"
    timeout: "10s"
```

Updates use TCP and support A, AAAA, and TXT records. Updating a record atomically
replaces its name/type RRset; deleting removes the specified value only.
Record listing uses AXFR of the authoritative zone, filtered to `dns.domain`,
so the server must allow both dynamic updates and zone transfers from this
client. AXFR is separate from RFC 2136: a server that only permits UPDATE can
receive updates, but cleanup will fail explicitly without AXFR permission.

TSIG signs updates and transfers. The key name, base64 secret, and algorithm must
match the server configuration. Supported algorithms are `hmac-sha1`,
`hmac-sha224`, `hmac-sha256` (default), `hmac-sha384`, and `hmac-sha512`, with or
without a trailing dot. Prefer SHA-256 or stronger. Omit all TSIG fields only
when the server explicitly allows unsigned requests, for example by source IP.
TSIG authenticates traffic but does not encrypt it.

Each option accepts a matching flag (`--rfc2136-server`, `--rfc2136-zone`,
`--rfc2136-tsig-key-name`, `--rfc2136-tsig-secret`, `--rfc2136-tsig-algorithm`,
`--rfc2136-timeout`) or environment variable (`RFC2136_SERVER`, `RFC2136_ZONE`,
`RFC2136_TSIG_KEY_NAME`, `RFC2136_TSIG_SECRET`, `RFC2136_TSIG_ALGORITHM`,
`RFC2136_TIMEOUT`). Avoid passing secrets as flags where process listings can
expose them.

For BIND, generate a key with `tsig-keygen -a hmac-sha256 dnsscale.`, include the
generated key in the server configuration, and configure the authoritative zone:

```bind
zone "example.com" {
    type primary;
    file "/var/lib/bind/db.example.com";
    update-policy { grant dnsscale. subdomain nodes.example.com. A AAAA TXT; };
    allow-transfer { key dnsscale.; };
};
```

The zone file and its directory must be writable by BIND for its dynamic-update
journal. Copy the generated key's secret into the client configuration securely.

### Application Settings

- `app.workers`: Number of worker goroutines (default: 2)
- `app.poll_interval`: How often to poll Tailscale API (default: 30s)
- `app.required_tags`: Only manage devices with these tags (optional)

### Logging

- `logging.level`: Log level (`debug`, `info`, `warn`, `error`)
- `logging.format`: Log format (`json` or `console`)

## How It Works

1. **Device Discovery**: DNSScale polls the Tailscale API to discover devices in your network
2. **DNS Record Creation**: For each device, it creates:
   - A record (IPv4) pointing to the device's Tailscale IP
   - AAAA record (IPv6) pointing to the device's Tailscale IPv6 address
   - TXT record for ownership tracking
3. **Continuous Monitoring**: Regularly checks for device changes and updates DNS accordingly
4. **Cleanup**: When devices are removed from Tailscale, their DNS records are automatically deleted

## DNS Record Format

For a device named `web-server` in domain `example.com`:

- **A Record**: `web-server.example.com` → `100.64.1.1`
- **AAAA Record**: `web-server.example.com` → `fd7a:115c:a1e0::1`
- **TXT Record**: `web-server.example.com` → `"dnsscale-managed node_id=123456"`

## Prerequisites

### Tailscale API Key

1. Go to https://login.tailscale.com/admin/settings/keys
2. Create a new API key with appropriate permissions
3. Use the key in your configuration

### Cloudflare Setup

1. Get your Zone ID from the Cloudflare dashboard
2. Create an API token at https://dash.cloudflare.com/profile/api-tokens
3. Grant the token `Zone:Read` and `DNS:Edit` permissions for your domain

### Route53 Setup

1. Ensure you have AWS credentials configured (via AWS CLI, environment variables, or IAM roles)

    a. If using AWS environment variables the AWS sdk looks for `AWS_ACCESS_KEY_ID` and  `AWS_SECRET_ACCESS_KEY`.

1. Get the Hosted Zone ID from the Route53 console

1. Ensure your AWS credentials have permissions to manage DNS records in the zone

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDNSZoneAccess",
                "Effect": "Allow",
                "Action": [
                    "route53:GetChange",
                    "route53:GetHostedZone",
                    "route53:ChangeResourceRecordSets",
                    "route53:ListResourceRecordSets"
                ],
                "Resource": [
                    "arn:aws:route53:::change/*",
                    "arn:aws:route53:::hostedzone/<your-zone-id>"
                ]
            },
            {
                "Sid": "ListZones",
                "Effect": "Allow",
                "Action": [
                    "route53:ListHostedZonesByName",
                    "route53:ListHostedZones"
                ],
                "Resource": "*"
            }
        ]
    }
    ```

## Tag Filtering

You can configure DNSScale to only manage devices with specific tags:

```yaml
app:
  required_tags:
    - "tag:production"
    - "tag:webserver"
```

Only devices with these tags will have DNS records created.

## Logging

DNSScale provides structured logging with configurable levels:

- **debug**: Detailed information for troubleshooting
- **info**: General operational information
- **warn**: Warning messages
- **error**: Error messages

Logs can be output in JSON format for structured logging systems or console format for human readability.

## Command Reference

### Main Commands

- `dnsscale`: Run the DNS management service
- `dnsscale config example`: Generate an example configuration file

### Global Flags

- `--config`: Path to configuration file
- `--log-level`: Set logging level
- `--log-format`: Set logging format
- `--workers`: Number of worker goroutines
- `--poll-interval`: Tailscale API poll interval

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Verify your API keys and permissions
2. **DNS Record Not Created**: Check if device has required tags (if configured)
3. **Rate Limiting**: Increase poll interval if hitting API rate limits

### Debug Mode

Run with debug logging to see detailed information:

```bash
./dnsscale --log-level debug
```

### Checking DNS Records

Verify DNS records were created:

```bash
dig web-server.example.com
nslookup web-server.example.com
```

## Security Considerations

- Store API keys securely (use environment variables or secure configuration management)
- Use least-privilege access for API tokens
- Consider using IAM roles instead of API keys where possible
- Regularly rotate API keys

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT
