"""Cost model for the cloud-native detection architecture.

The model turns a measured event volume into a monthly bill so that the
architecture can be compared against the value of what it protects. It is a
*list-price* model: it uses published on-demand prices for a single commercial
region and ignores committed-use discounts, free tiers beyond the first month,
data-transfer between AZs and taxes. Prices drift, so they live in one table
here and are reported in the paper with the date they were taken.

Every quantity is derived from measurable properties of the testbed (events per
day, bytes per event, telemetry archive growth), which means the model can be
re-run against a different mission profile by changing only :class:`Workload`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

#: Unit prices, US East (N. Virginia) on-demand list prices, collected 2026-01.
#: Keys are stable so the table can be replaced wholesale for another region.
PRICES: Dict[str, float] = {
    "kinesis_ondemand_stream_hour": 0.040,        # per stream-hour
    "kinesis_ondemand_gb_ingested": 0.080,        # per GB
    "lambda_gb_second": 0.0000166667,
    "lambda_per_million_requests": 0.20,
    "cloudwatch_logs_gb_ingested": 0.50,
    "cloudwatch_logs_gb_month_stored": 0.03,
    "cloudwatch_custom_metric_month": 0.30,
    "cloudwatch_alarm_month": 0.10,
    "s3_standard_gb_month": 0.023,
    "s3_put_per_1000": 0.005,
    "s3_get_per_1000": 0.0004,
    "cloudtrail_data_event_per_100k": 0.10,
    "eventbridge_per_million_events": 1.00,
    "opensearch_serverless_ocu_hour": 0.24,
    "securityhub_finding_per_10k": 0.30,
    "securityhub_check_month": 0.0010,
    "guardduty_gb_analyzed": 1.00,
    "kms_key_month": 1.00,
    "kms_per_10k_requests": 0.03,
    "sns_per_million_notifications": 0.50,
}


@dataclass
class Workload:
    """Measured or projected volume for one month of operations."""

    spacecraft: int = 1
    ground_stations: int = 1
    security_events_per_day: float = 800.0
    bytes_per_event: int = 900
    telemetry_objects_per_day: float = 60.0
    telemetry_object_mb: float = 48.0
    archive_retention_months: float = 12.0
    findings_per_day: float = 3.0
    lambda_ms_per_event: float = 45.0
    lambda_memory_mb: int = 512
    opensearch_ocus: float = 2.0            # minimum billable indexing+search
    cloudwatch_alarms: int = 25
    custom_metrics: int = 40
    days: float = 30.0

    def scaled(self, spacecraft: int) -> "Workload":
        """Linear scale-out of the per-spacecraft components."""
        f = spacecraft / max(self.spacecraft, 1)
        return Workload(
            spacecraft=spacecraft,
            ground_stations=max(1, round(self.ground_stations * f)),
            security_events_per_day=self.security_events_per_day * f,
            bytes_per_event=self.bytes_per_event,
            telemetry_objects_per_day=self.telemetry_objects_per_day * f,
            telemetry_object_mb=self.telemetry_object_mb,
            archive_retention_months=self.archive_retention_months,
            findings_per_day=self.findings_per_day * f,
            lambda_ms_per_event=self.lambda_ms_per_event,
            lambda_memory_mb=self.lambda_memory_mb,
            opensearch_ocus=max(2.0, self.opensearch_ocus * (f ** 0.6)),
            cloudwatch_alarms=self.cloudwatch_alarms,
            custom_metrics=self.custom_metrics,
            days=self.days,
        )


@dataclass
class CostLine:
    service: str
    driver: str
    quantity: float
    unit: str
    monthly_usd: float


@dataclass
class CostReport:
    workload: Workload
    lines: List[CostLine] = field(default_factory=list)

    @property
    def total(self) -> float:
        return sum(line.monthly_usd for line in self.lines)

    @property
    def per_spacecraft(self) -> float:
        return self.total / max(self.workload.spacecraft, 1)

    def as_table(self) -> str:
        rows = ["| Service | Cost driver | Quantity | Unit | USD/month |",
                "|---|---|---:|---|---:|"]
        for ln in sorted(self.lines, key=lambda x: -x.monthly_usd):
            rows.append(
                f"| {ln.service} | {ln.driver} | {ln.quantity:,.1f} | {ln.unit} | "
                f"{ln.monthly_usd:,.2f} |")
        rows.append(f"| **Total** | | | | **{self.total:,.2f}** |")
        return "\n".join(rows)


def estimate(w: Workload) -> CostReport:
    p = PRICES
    r = CostReport(workload=w)
    add = lambda *a: r.lines.append(CostLine(*a))  # noqa: E731

    events_month = w.security_events_per_day * w.days
    gb_events = events_month * w.bytes_per_event / 1e9

    add("Kinesis Data Streams", "stream-hours (on-demand)",
        24 * w.days * max(1, w.spacecraft // 25 + 1), "stream-hour",
        24 * w.days * max(1, w.spacecraft // 25 + 1) * p["kinesis_ondemand_stream_hour"])
    add("Kinesis Data Streams", "ingested telemetry + security events", gb_events, "GB",
        gb_events * p["kinesis_ondemand_gb_ingested"])

    gb_s = (w.lambda_memory_mb / 1024) * (w.lambda_ms_per_event / 1000) * events_month
    add("Lambda", "detection + response invocations", events_month, "invocation",
        events_month / 1e6 * p["lambda_per_million_requests"] + gb_s * p["lambda_gb_second"])

    add("CloudWatch Logs", "log ingestion", gb_events, "GB",
        gb_events * p["cloudwatch_logs_gb_ingested"])
    add("CloudWatch Logs", "log retention", gb_events * 3, "GB-month",
        gb_events * 3 * p["cloudwatch_logs_gb_month_stored"])
    add("CloudWatch", "alarms + custom metrics", w.cloudwatch_alarms + w.custom_metrics,
        "resource",
        w.cloudwatch_alarms * p["cloudwatch_alarm_month"]
        + w.custom_metrics * p["cloudwatch_custom_metric_month"])

    objects_month = w.telemetry_objects_per_day * w.days
    gb_archive = objects_month * w.telemetry_object_mb / 1024
    stored = gb_archive * w.archive_retention_months
    add("S3", "telemetry archive storage", stored, "GB-month",
        stored * p["s3_standard_gb_month"])
    add("S3", "PUT/GET requests", objects_month * 6, "request",
        objects_month / 1000 * p["s3_put_per_1000"]
        + objects_month * 5 / 1000 * p["s3_get_per_1000"])
    add("CloudTrail", "S3 data events", objects_month * 6, "event",
        objects_month * 6 / 100_000 * p["cloudtrail_data_event_per_100k"])

    add("EventBridge", "rule matches", events_month, "event",
        events_month / 1e6 * p["eventbridge_per_million_events"])
    add("OpenSearch Serverless", "indexing + search OCUs", w.opensearch_ocus * 24 * w.days,
        "OCU-hour", w.opensearch_ocus * 24 * w.days * p["opensearch_serverless_ocu_hour"])
    add("Security Hub", "findings ingested", w.findings_per_day * w.days, "finding",
        w.findings_per_day * w.days / 10_000 * p["securityhub_finding_per_10k"] + 5.0)
    add("GuardDuty", "CloudTrail + S3 data analysed", gb_events, "GB",
        gb_events * p["guardduty_gb_analyzed"])
    add("KMS", "key + cryptographic requests", 2, "key",
        2 * p["kms_key_month"] + (events_month / 10_000) * p["kms_per_10k_requests"])
    add("SNS", "analyst notifications", w.findings_per_day * w.days, "notification",
        w.findings_per_day * w.days / 1e6 * p["sns_per_million_notifications"])
    return r


def scaling_table(base: Workload, fleet_sizes=(1, 10, 100)) -> str:
    rows = ["| Spacecraft | Events/day | USD/month | USD/spacecraft/month |",
            "|---:|---:|---:|---:|"]
    for n in fleet_sizes:
        w = base.scaled(n)
        rep = estimate(w)
        rows.append(f"| {n} | {w.security_events_per_day:,.0f} | {rep.total:,.2f} | "
                    f"{rep.per_spacecraft:,.2f} |")
    return "\n".join(rows)
