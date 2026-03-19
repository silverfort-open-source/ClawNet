# ClawNet by SilverFort
<img width="849" height="223" alt="image" src="https://github.com/silverfort-open-source/ClawNet/blob/main/Logo.png" />

ClawNet is an OpenClaw plugin that adds a safety review step to skill installation workflows from ClawHub.

## Why We Created ClawNet 

ClawNet was created as part of our research into the ClawHub download and installation flow, where we explored how community-delivered skills could introduce risk into agent environments. This plugin is a practical outcome of that work: a lightweight safeguard designed to review skill installs before they are allowed to proceed. [You can read the full research here.]()

## How It Works

1. ClawNet detects a ClawHub's skill installation request.
2. It retrieves the skill content when available.
3. It sends the request for review through the OpenClaw gateway chat-completions endpoint.
4. The review returns `suspicious`, `severity`, and an optional `reason`.
5. If the review does not raise concerns, the installation proceeds normally.
6. If `suspicious` is `true`, the installation is blocked.

## What It Looks For

During review the LLM will searches for:
- Suspicious or misleading instructions
- Hidden or unsafe behavior
- Credential theft or secret exposure
- Risky remote execution patterns
- Other indicators that a skill may not be safe to install

## Requirements

To use ClawNet, you need:

**1. A reachable OpenClaw gateway.**
**2. The gateway chat-completions endpoint enabled.** In `openclaw.json`:
```json
{
  "gateway": {
    "http": {
      "endpoints": {
        "chatCompletions": {
          "enabled": true
        }
      }
    }
  }
}
```
After updating configuration, restart the gateway:
```bash
openclaw gateway restart
```
**3. Gateway authentication configured with either a token or a password.** This can be done via:
- Plugin configuration: `gatewayAuthToken` or `gatewayAuthPassword`.
- Main gateway auth configurations.
- Environmental variables: `OPENCLAW_GATEWAY_TOKEN` or `OPENCLAW_GATEWAY_PASSWORD`.

Use either a token or a password. The plugin must be able to access one of them using one of the methods described above.

## Installation

Install from a local directory:

```bash
openclaw plugins install -l /path/to/ClawNet
```

## Configuration

ClawNet supports the following configuration values:

| Key | Description |
| --- | --- |
| `gatewayHost` | Hostname of the OpenClaw gateway |
| `gatewayPort` | Port of the OpenClaw gateway |
| `gatewayAuthToken` | Authentication token for the gateway |
| `gatewayAuthPassword` | Authentication password for the gateway |

If you are using plugin-level configuration, a typical setup looks like this:

```json
{
  "plugins": {
    "entries": {
      "ClawNet": {
        "enabled": true,
        "config": {
          "gatewayHost": "127.0.0.1",
          "gatewayPort": 18789,
          "gatewayAuthToken": "your-token"
        }
      }
    }
  }
}
```

## Limitations

- ClawNet is focused on ClawHub-related installation activity.
- Review results depend on the gateway model and configuration in use.
- ClawNet reviews fetched skill content when available, but very large files may be truncated and some installs may be assessed with limited context if the file cannot be retrieved.
- As with any safety system, this plugin should be treated as an additional protective layer rather than a guarantee.
