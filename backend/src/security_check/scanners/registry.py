from __future__ import annotations

from dataclasses import dataclass

from security_check.scanners.base import Scanner


@dataclass(frozen=True)
class ScannerRegistry:
    scanners: dict[str, Scanner]

    def list(self) -> list[Scanner]:
        return [self.scanners[k] for k in sorted(self.scanners.keys())]

    def get(self, scanner_id: str) -> Scanner | None:
        return self.scanners.get(scanner_id)

