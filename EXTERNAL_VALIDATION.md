# External Validation Status

## Current evidence

The detector families are compared on a common 11-feature host-window schema. The
stronger internal dataset contains 2,000 generated windows with overlapping behavior
profiles and label noise. It is useful for detector comparison but is not operational
endpoint telemetry.

## Authoritative external source

Los Alamos National Laboratory publishes a de-identified 90-day unified host and
network dataset collected from enterprise Windows systems and routers. The host
records include authentication and process events, while the network records include
bidirectional flow counts and bytes. The dataset landing page and citation are:

- https://csr.lanl.gov/data/2017/
- M. Turcotte, A. Kent, and C. Hash, "Unified Host and Network Data Set," 2018.

## Required adapter and claim boundary

LANL does not directly provide the current 11 window features. CPU, memory, disk-write
volume, file entropy, rename counts, unsigned execution, extension change, and
shadow-copy activity cannot be reconstructed from its published schema. Mapping only
the available process/network fields and filling the rest with zeros would create a
misleading evaluation.

The next valid external run therefore requires Sysmon/EDR or other authorized endpoint
telemetry that actually contains the filesystem and process signals used by the model,
or a revised reduced-feature detector trained and evaluated as a separate experiment.
No real-endpoint F1 is claimed until one of those paths is completed.
