# Spring Boot Actuator Advanced Detection Templates

**Author:** [Shafranpackeer](https://github.com/Shafranpackeer)
**Contribution to:** [RedAmon](https://github.com/samugit83/redamon)

## Overview

This contribution adds comprehensive Spring Boot Actuator vulnerability detection with advanced WAF bypass techniques. These templates go beyond basic endpoint discovery to include:

- **85+ path variations** with encoding bypasses
- **CloudFront/AWS WAF bypass** techniques (URL encoding)
- **Semicolon injection** bypasses (Spring parser quirk)
- **RCE chain detection** (Jolokia, Gateway, env+refresh)
- **Credential extraction** from heapdump/env

## Templates Included

| Template | Severity | Description |
|----------|----------|-------------|
| `springboot-actuator-discovery-bypass.yaml` | Medium | Discovery with 85+ path variations & WAF bypasses |
| `springboot-heapdump-bypass.yaml` | Critical | Heapdump detection with $55K bug bounty techniques |
| `springboot-env-bypass.yaml` | High | Environment exposure with secret key extraction |
| `springboot-gateway-ssrf.yaml` | High-Critical | Gateway SSRF + CVE-2022-22947 RCE |
| `springboot-jolokia-rce.yaml` | Critical | Jolokia RCE chains (XXE, JNDI, property extraction) |
| `springboot-sensitive-endpoints.yaml` | High | All sensitive endpoints (mappings, beans, trace, etc.) |
| `springboot-env-rce-chains.yaml` | Critical | RCE prerequisites (env+refresh, H2 console, logview LFI) |
| `springboot-actuator-paths.txt` | N/A | 200+ path wordlist for fuzzing |

## Bypass Techniques Included

### 1. URL Encoding Bypass (CloudFront WAF)
```
/%61ctuator/heapdump     # 'a' encoded
/a%63tuator/heapdump     # 'c' encoded
/actuator/heapdump%23    # Hash bypass (confuses WAF)
/%61%63%74%75%61%74%6F%72/heapdump  # Fully encoded
```

### 2. Semicolon Bypass (Spring Parser Quirk)
```
/actuator;/heapdump      # Spring removes ; but WAF doesn't
/;/actuator/heapdump     # Prefix semicolon
/actuator;.json/heapdump # Extension confusion
```

### 3. Path Traversal Variations
```
//actuator/heapdump      # Double slash
/./actuator/heapdump     # Dot-slash
/actuator//heapdump      # Mid-path double slash
/actuator/heapdump/      # Trailing slash
```

### 4. Alternate Base Paths
```
/manage/heapdump
/management/heapdump
/admin/actuator/heapdump
/monitor/heapdump
/mgmt/heapdump
/api/actuator/heapdump
/internal/actuator/heapdump
```

## RCE Chains Detected

### Jolokia RCE
- `reloadByURL` - Logback JNDI/XXE injection
- `createJNDIRealm` - Tomcat JNDI injection
- Property extraction via MBeans

### Gateway RCE (CVE-2022-22947)
- SpEL expression injection in route definitions
- SSRF via route manipulation
- Affects Spring Cloud Gateway < 3.1.0 / 3.0.6

### Env + Refresh/Restart RCE
- `eureka.client.serviceUrl.defaultZone` - XStream deserialization
- `logging.config` - Logback JNDI/Groovy execution
- `spring.datasource.url` - JDBC deserialization
- `spring.cloud.bootstrap.location` - SnakeYAML deserialization

## Real-World Impact

- **Volkswagen Breach**: Heapdump exposed AWS credentials leading to 9TB GPS data leak
- **$55,000+ Bug Bounty**: Single heapdump exposure with WAF bypass
- **OAuth Bypass**: Env credentials used to bypass MFA via ROPC flow

## Installation

Copy templates to your Nuclei templates directory:

```bash
# Option 1: Direct to nuclei templates
cp *.yaml ~/.nuclei-templates/http/misconfiguration/springboot/

# Option 2: RedAmon project
cp *.yaml redamon/mcp/nuclei-templates/http/misconfiguration/springboot/
```

## Usage

```bash
# Run all Spring Boot templates
nuclei -u https://target.com -t springboot-*.yaml

# Run with increased verbosity
nuclei -u https://target.com -t springboot-actuator-discovery-bypass.yaml -v

# Use wordlist for fuzzing
ffuf -u https://target.com/FUZZ -w springboot-actuator-paths.txt -mc 200,302,401,403
```

## References

- [HackTricks - Spring Actuators](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators)
- [Wiz Blog - Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [0xn3va Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators)
- [DSecured - Actuator Bypasses](https://www.dsecured.com/en/articles/spring-boot-actuator-using-misconfig-to-your-advantage-paths-bypasses-techniques)
- [Spring Boot Vulnerability Exploits](https://github.com/LandGrey/SpringBootVulExploit)

## CVEs Covered

| CVE | Description | Severity |
|-----|-------------|----------|
| CVE-2022-22947 | Spring Cloud Gateway SpEL RCE | Critical |
| CVE-2021-21234 | Logview Path Traversal | High |
| CVE-2018-1000130 | Jolokia JNDI Injection | Critical |
| CVE-2018-1000129 | Jolokia XSS | Medium |
| CVE-2025-22235 | Endpoint Access Control Bypass | Medium |

## License

MIT License - Free to use for authorized security testing only.

## Disclaimer

These templates are for **authorized security testing only**. Always obtain proper authorization before testing any systems. The author is not responsible for misuse.
