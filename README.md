# Proof of Concept (PoC): Exploiting Race Conditions in Jersey Client Version 3.1.9
This PoC demonstrates a race condition vulnerability in Jersey Client 3.1.9. When a race condition occurs, the second REST call loses critical SSL configurations, including mutual authentication, custom key/trust stores, and other security settings.
The vulnerability, as demonstrated in the provided code, has potential for a CVE classification due to its severity and impact.
