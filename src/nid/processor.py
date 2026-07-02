from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import time
from typing import Protocol

from .alerts import send_alerts_with_status
from .blocking import block_ip
from .mitre import map_attack, mitre_summary
from .postgres import PostgresRepository
from .realtime import DetectionEvent, RealTimeDetector
from .storage import save_external
from .threat_intel import enrich_event


class EventRepository(Protocol):
    def save(self, event: DetectionEvent) -> int: ...

    def record_response(self, source_ip: str, action: str, details: str) -> int: ...


@dataclass
class ProcessingPolicy:
    use_external_threat_intel: bool = False
    save_events: bool = True
    save_external: bool = True
    send_notifications: bool = False
    alert_min_severity: str = "High"
    auto_block: bool = False
    auto_response: bool = False
    alert_cooldown_seconds: int = 300
    block_min_confidence: float = 0.90
    block_min_threat_score: float = 75.0
    block_min_severity: str = "High"


@dataclass
class ProcessingResult:
    event: DetectionEvent
    actions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class RealTimeProcessor:
    """Run detection, enrichment, logging, alerting, and response for each window."""

    def __init__(
        self,
        model_path: str | Path = "models/sample_ensemble.joblib",
        threshold: float = 0.75,
        min_packets: int = 10,
        live_xai_mode: str = "adaptive",
        policy: ProcessingPolicy | None = None,
        store: EventRepository | None = None,
    ) -> None:
        self.detector = RealTimeDetector(model_path, threshold=threshold, min_packets=min_packets)
        self.policy = policy or ProcessingPolicy()
        self.live_xai_mode = live_xai_mode
        self.store = store
        if self.policy.save_events and self.store is None:
            self.store = PostgresRepository()
        self._blocked_ips: set[str] = set()
        self._last_alerts: dict[tuple[str, str], float] = {}

    def process_live_window(
        self,
        interface: str | None,
        window_seconds: float,
        packet_limit: int = 500,
        debug_packets: bool = False,
    ) -> ProcessingResult:
        started = time.perf_counter()
        event = self.detector.detect_live_window(
            interface,
            window_seconds,
            xai_mode=self.live_xai_mode,
            packet_limit=packet_limit,
            debug_packets=debug_packets,
        )
        processing_started = time.perf_counter()
        result = self.process_event(event)
        statistics = result.event.statistics or {}
        statistics["integration_latency_ms"] = round((time.perf_counter() - processing_started) * 1000, 1)
        statistics["total_latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        statistics["window_latency_ms"] = statistics["total_latency_ms"]
        result.event.statistics = statistics
        return result

    def process_file(self, csv_path: str | Path) -> ProcessingResult:
        return self.process_event(self.detector.detect_file(csv_path))

    def process_event(self, event: DetectionEvent) -> ProcessingResult:
        result = ProcessingResult(event=event)
        self._enrich_mitre(event)
        try:
            intel = enrich_event(event, use_external=self.policy.use_external_threat_intel)
            labels = ", ".join(intel.labels or ["no blacklist match"])
            result.actions.append(
                f"threat intelligence: score {intel.score:.0f}%, status {intel.status}, "
                f"provider {intel.provider}, country {intel.country}, {labels}"
            )
        except Exception as error:
            result.errors.append(f"Threat intelligence: {error}")

        if event.source_ip in self._blocked_ips:
            event.blocked = True

        has_packets = event.rows > 0

        if self.policy.save_events and self.store is not None and has_packets:
            try:
                result.actions.append(f"PostgreSQL event #{self.store.save(event)}")
            except Exception as error:
                result.errors.append(f"PostgreSQL logging: {error}")
        elif self.policy.save_events and not has_packets:
            result.actions.append("No packets captured; database logging skipped")

        if self.policy.save_external and has_packets:
            try:
                result.actions.extend(f"{name} logged" for name in save_external(event))
            except Exception as error:
                result.errors.append(f"External database logging: {error}")

        if (
            self._notifications_enabled()
            and event.predicted_attack
            and self._meets_notification_severity(event)
            and self._should_notify(event)
        ):
            try:
                delivery = send_alerts_with_status(event)
                result.actions.extend(f"{channel} alert sent" for channel in delivery.sent)
                result.errors.extend(f"Notification {error}" for error in delivery.errors)
                if not delivery.sent and not delivery.errors:
                    result.actions.append("no alert channels configured")
                if delivery.sent:
                    self._last_alerts[(event.source_ip, event.category)] = time.monotonic()
            except Exception as error:
                result.errors.append(f"Notifications: {error}")
        elif self._notifications_enabled() and event.predicted_attack and self._meets_notification_severity(event):
            result.actions.append("duplicate alert suppressed by cooldown")

        if self._should_block(event):
            try:
                block_details = block_ip(event.source_ip, execute=True)
                event.blocked = True
                self._blocked_ips.add(event.source_ip)
                result.actions.append(f"blocked {event.source_ip}")
                if self.policy.save_events and self.store is not None:
                    self.store.record_response(event.source_ip, "block", block_details)
                    result.actions.append("block response logged")
            except Exception as error:
                result.errors.append(f"Automatic blocking: {error}")
        return result

    @staticmethod
    def _enrich_mitre(event: DetectionEvent) -> None:
        stats = event.statistics or {}
        mappings = map_attack(event.category, str(stats.get("rule_engine_signature_ids", "")))
        summary = mitre_summary(mappings)
        stats["mitre_attack"] = mappings
        stats.update(summary)
        event.statistics = stats

    def _should_block(self, event: DetectionEvent) -> bool:
        if not (self.policy.auto_block or self.policy.auto_response) or not event.predicted_attack or not event.source_ip:
            return False
        if event.source_ip in self._blocked_ips:
            return False
        if not self._meets_severity(event, self.policy.block_min_severity):
            return False
        try:
            if not ipaddress.ip_address(event.source_ip).is_global:
                return False
        except ValueError:
            return False
        return (
            event.confidence >= self.policy.block_min_confidence
            or event.threat_score >= self.policy.block_min_threat_score
        )

    def _should_notify(self, event: DetectionEvent) -> bool:
        last_sent = self._last_alerts.get((event.source_ip, event.category))
        if last_sent is None:
            return True
        return time.monotonic() - last_sent >= self.policy.alert_cooldown_seconds

    def _meets_alert_severity(self, event: DetectionEvent) -> bool:
        return self._meets_severity(event, self.policy.alert_min_severity)

    def _meets_notification_severity(self, event: DetectionEvent) -> bool:
        minimum = self.policy.alert_min_severity if self.policy.send_notifications else "High"
        return self._meets_severity(event, minimum)

    def _notifications_enabled(self) -> bool:
        return self.policy.send_notifications or self.policy.auto_response

    @staticmethod
    def _meets_severity(event: DetectionEvent, minimum: str) -> bool:
        ranks = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        return ranks.get(event.severity, 0) >= ranks.get(minimum, 2)
