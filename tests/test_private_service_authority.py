from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "private_service_authority",
    ROOT / "scripts" / "validate_private_service_authority.py",
)
assert SPEC is not None and SPEC.loader is not None
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)


class PrivateServiceAuthorityTests(unittest.TestCase):
    def test_compose_short_port_publication_is_denied(self) -> None:
        source = 'services:\n  exporter:\n    ports: ["9187:9187"]\n'
        violations = AUTHORITY.public_exposure_violations(
            Path("deploy/compose.yaml"),
            source.lower(),
        )
        self.assertIn("host port publication for 9187", violations)

    def test_compose_long_port_publication_is_denied(self) -> None:
        source = (
            "services:\n"
            "  exporter:\n"
            "    ports:\n"
            "      - target: 9187\n"
            "        published: 9187\n"
        )
        violations = AUTHORITY.public_exposure_violations(
            Path("deploy/compose.yaml"),
            source.lower(),
        )
        self.assertIn("host port publication for 9187", violations)
        self.assertIn("published/host port 9187", violations)

    def test_container_listener_is_not_host_publication(self) -> None:
        violations = AUTHORITY.public_exposure_violations(
            Path("config/codestra/runtime.v1.json"),
            '{"listenAddress":"0.0.0.0:9187"}'.lower(),
        )
        self.assertEqual(violations, ())

    def test_edge_proxy_to_exporter_is_denied(self) -> None:
        source = "reverse_proxy postgres-exporter:9187"
        violations = AUTHORITY.public_exposure_violations(
            Path("deploy/Caddyfile"),
            source.lower(),
        )
        self.assertIn("route to the private exporter", violations)

    def test_declarative_kong_route_is_denied(self) -> None:
        source = (
            "_format_version: '3.0'\n"
            "services:\n"
            "  - name: postgres-exporter\n"
            "    url: http://postgres-exporter:9187\n"
            "    routes:\n"
            "      - name: public-exporter\n"
            "        paths: [/metrics]\n"
        )
        violations = AUTHORITY.public_exposure_violations(
            Path("kong/declarative.yaml"),
            source.lower(),
        )
        self.assertIn("declarative Kong route to the private exporter", violations)

    def test_kubernetes_load_balancer_is_denied(self) -> None:
        source = (
            "apiVersion: v1\n"
            "kind: Service\n"
            "spec:\n"
            "  type: LoadBalancer\n"
            "  ports:\n"
            "    - port: 9187\n"
            "      targetPort: 9187\n"
        )
        violations = AUTHORITY.public_exposure_violations(
            Path("k8s/postgres-exporter.yaml"),
            source.lower(),
        )
        self.assertIn("public Kubernetes Service for 9187", violations)

    def test_kubernetes_host_port_is_denied(self) -> None:
        source = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - ports:\n"
            "            - containerPort: 9187\n"
            "              hostPort: 9187\n"
        )
        violations = AUTHORITY.public_exposure_violations(
            Path("helm/templates/deployment.yaml"),
            source.lower(),
        )
        self.assertIn("published/host port 9187", violations)

    def test_private_kubernetes_ports_are_allowed(self) -> None:
        service = (
            "apiVersion: v1\n"
            "kind: Service\n"
            "spec:\n"
            "  type: ClusterIP\n"
            "  ports:\n"
            "    - port: 9187\n"
            "      targetPort: 9187\n"
        )
        deployment = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - ports:\n"
            "            - containerPort: 9187\n"
        )
        for path, source in (
            (Path("k8s/service.yaml"), service),
            (Path("helm/templates/deployment.yaml"), deployment),
        ):
            with self.subTest(path=path):
                violations = AUTHORITY.public_exposure_violations(path, source.lower())
                self.assertEqual(violations, ())


if __name__ == "__main__":
    unittest.main()
