# HAPI FHIR JPA Server (real) mocks

Genuine **HAPI FHIR JPA Server Starter** instances for integration-testing
OIDA's `fhir` scanner against a real FHIR server (not the Python simulation in
`../mock/`).

## License / provenance

- Project: <https://github.com/hapifhir/hapi-fhir-jpaserver-starter>
- License: **Apache-2.0**
- Image: official `hapiproject/hapi` published to Docker Hub by the project.
  We pin a stable tag and pull it at runtime - **no jars or binaries are
  vendored into this repo**. Only the `application-*.yaml` config files here are
  committed.

Each server is a Spring-Boot app with an **embedded H2 database** (in-memory,
no external DB) serving a full FHIR REST API at `/fhir` on container port 8080
(CapabilityStatement at `/fhir/metadata`, CRUD + search + `$validate`).

## Configurations

| compose service      | host port | fhir_version | posture                                                        |
|----------------------|-----------|--------------|----------------------------------------------------------------|
| `fhir-hapi-r4`       | 8090      | R4 (4.0.1)   | permissive: no validation, external refs allowed, CORS open    |
| `fhir-hapi-r5`       | 8091      | R5 (5.0.0)   | permissive: R5 CapabilityStatement, distinct schema            |
| `fhir-hapi-r4-strict`| 8092      | R4 (4.0.1)   | strict: request+response validation, external refs blocked, bundle types restricted |

Config is supplied to Spring Boot via `--spring.config.location` pointing at the
mounted yaml. Spring relaxed-binding also allows env-var overrides
(e.g. `HAPI_FHIR_FHIR_VERSION`).

HAPI takes ~30-60s to boot; the compose healthchecks use a 90s `start_period`.
