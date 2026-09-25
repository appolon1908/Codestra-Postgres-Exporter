# Upgrade and upstream synchronization

Upstream source import and runtime release selection are separate reviewed changes. Resolve the selected upstream tag to a 40-character commit and the multi-platform image to a manifest-list digest. Record the target platform digest, attempt signature/provenance verification, scan the exact image, and update the runtime lock, fixed Compose identity and compatibility tests together.

Validate the least-privilege role against a disposable supported PostgreSQL version, bound collection time, metric cardinality, private exposure, configuration checksum and exact image version. Promote only protected merges. Preserve a pullable previous digest/config artifact/checksum and document schema/collector compatibility before a runtime release. A floating branch or tag is never a production identity.
