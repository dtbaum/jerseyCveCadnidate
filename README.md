# jerseyCveCandidate
A PoC which exploit race condition of jersey client, version 3.1.9

In the case of a race condition, the second REST call loses critical SSL settings such as mutual authentication, customized key/trust stores, and other configurations - in best case this leads to SSLHandshakeException.
The worst case (see code) is a candidate for a CVE.
