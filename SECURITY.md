# Security Policy

The LF Edge FIDO Device Onboard (FDO) project is committed to addressing security vulnerabilities.

To report a potential security issue or vulnerability please [email your report to the LF Edge FDO Security team](mailto:FDO-Security@lists.lfedge.org?subject=%5Bgo-fdo%5D%20Security%20Vulnerability&body=Summary%20of%20Vulnerability%3A%0A%0ADescription%20and%20Results%3A%0A%0AAffected%20Versions%3A%0A%0ASteps%20to%20Replicate%3A%0A%0ACommon%20Vulnerability%20Scoring%20System%20%28CVSS%29%20Base%20Score%3A%0A%0ACVSS%20Vector%20String%3A%0A%0AKnown%20Disclosure%20Plans%3A%0A).

When reporting, please provide as much of the following information as possible (also provided as a template in the above link):

|                                                       |                                                                                                                                               |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Summary of Vulnerability                              | Short description of the vulnerability                                                                                                        |
| Description and Results                               | Full description of the issue including any impacts to confidentiality, integrity, or availability as well as the expected and actual results |
| Affected Versions                                     | List of the potentially impacted versions                                                                                                     |
| Steps to Replicate[¹](#testing)                       | Describe your execution environment and the steps to reproduce the issue, including any sample code to trigger the vulnerability              |
| Common Vulnerability Scoring System (CVSS) Base Score | CVSS score if known                                                                                                                           |
| CVSS Vector String                                    | CVSS vector if known                                                                                                                          |
| Known Disclosure Plans                                | Any known disclosure plans and timelines                                                                                                      |

## Encrypting Security Disclosures

If you wish to encrypt your report we recommend [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) using tools like [GNU Privacy Guard](https://gnupg.org).

The project's security team rotates PGP public keys, so please first [send an email request](mailto:FDO-Security@lists.lfedge.org?subject=%5Bgo-fdo%5D%20Public%20Key%20Request&body=Please%20send%20the%20current%20security%20report%20PGP%20public%20key%2E) for the security team's _current_ PGP public key.

If you are having trouble encrypting your vulnerability report or have any questions about the process, please send a message to the [go-fdo LF Edge FDO Security team](mailto:FDO-Security@lists.lfedge.org?subject=%5Bgo-fdo%5D%20Help%20Needed). We’ll help identify a method for secure transmission of your report.

## Non Security Bugs

Reporting of bugs is managed using this project's [GitHub Issues](https://github.com/fido-device-onboard/go-fdo/issues).

Before reporting a new issue please first search the current open [Issues](https://github.com/fido-device-onboard/go-fdo/issues) and if you see a similar or matching issue, please comment in the issue with your findings[¹](#testing).

If there are no related issues:

1. From the [Issues](https://github.com/fido-device-onboard/go-fdo/issues) page, select `New Issue`
2. In the `Bug Report` row select `Get Started`. This will open a new page with a bug report template.
3. Fill in as much detail as possible following the prompts and examples in the template.

## Testing

> ¹ Please consider helping the project by extending test coverage. Whether you are reporting a security vulnerability or bug, if you are able to provide a unit or integration test that reproduces the issue, your contribution will expedite a resolution and also protect from future regressions.
