<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

A tool that checks whether a npm install or a curl | sh is malicious or not? 

## Demo

GoAudit checks for whether any important files like AWS credentials, Github credentials, SSH keys, etc. were reador not by running the commands in a sandbox.

```zsh
$ goaudit scan "cat ~/.aws/credentials"
[CRITICAL] File Read: /root/.aws/credentials
Verdict: CRITICAL ✗

$ goaudit scan "npm install lodash"
[WARNING] Network: registry.npmjs.org (104.16.2.34:443)
Verdict: WARNING
```

## Install 

```zsh
go install github.com/KushalMeghani1644/goAudit-CLI@latest
```

## Usage

```zsh
goaudit scan "npm install <package>"
goaudit scan "curl -fsSL https://example.com/install.sh | sh"
goaudit scan "npm install <package>" --ci   # JSON output
```

## Requirements

- Docker
- gVisor (recommended)
