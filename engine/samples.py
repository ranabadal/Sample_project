"""Production incident library with realistic, high-fidelity scenarios."""

from dataclasses import dataclass
from typing import List, Dict


@dataclass
class SampleIncident:
    title: str
    category: str
    description: str


SAMPLE_INCIDENTS: List[SampleIncident] = [
    SampleIncident(
        title="PostgreSQL RDS Connection Pool Exhaustion & Deadlock Contention",
        category="Database",
        description=(
            "CRITICAL ALERT: Production Postgres RDS cluster (prod-db-primary) hit 100% max_connections (500/500). "
            "API Gateway reports 504 Gateway Timeouts across checkout and auth services. Error log: 'FATAL: remaining "
            "connection slots are reserved for non-replication superuser connections'. pgbouncer pool mode is set to session, "
            "and client connections spiked from 120 to 1,500 after a batch reconciliation job started at 02:00 UTC. "
            "Active query analysis shows exclusive table lock on 'orders' table due to an unindexed migration running concurrently."
        ),
    ),
    SampleIncident(
        title="Kubernetes OOMKilled CrashLoopBackOff on Payment Processor",
        category="Infrastructure",
        description=(
            "Incident: Pod crashloop in namespace 'prod-payments'. Pod 'payment-processor-7c89f47bc5-x9z2q' terminated with "
            "exit code 137 (OOMKilled). Node memory pressure alert triggered on ip-10-0-4-88.ec2.internal. Replica count dropped "
            "from 12 to 3 healthy replicas. Heap dump metrics show Java JVM memory consumption climbing exponentially until container "
            "limit (2Gi) is breached within 4 minutes of launch. Outgoing payment confirmation requests are failing with connection refused."
        ),
    ),
    SampleIncident(
        title="CoreDNS Resolution Storm & Cluster-Wide NXDOMAIN Outage",
        category="Networking",
        description=(
            "Service-wide outage alert: All internal gRPC calls failing with 'dial tcp: lookup auth.internal.company.net on "
            "10.96.0.10:53: no such host (NXDOMAIN)'. CoreDNS deployment logs show CPU throttling and packet drops at upstream resolver "
            "1.1.1.1. Query volume spiked 800% after service deployment v2.4.1 which removed local in-memory DNS caching and "
            "introduced aggressive exponential retry loops without jitter."
        ),
    ),
    SampleIncident(
        title="Expired Production Wildcard SSL/TLS Ingress Certificate",
        category="Security",
        description=(
            "ALERT: Customers across all web and mobile apps receiving browser security warnings 'NET::ERR_CERT_DATE_INVALID' "
            "and 'SSL certificate expired'. Ingress controller nginx logs show TLS handshake failure for domain *.api.domain.com. "
            "Certificate validity window expired on 2026-10-14 00:00:00 UTC. Automatic Let's Encrypt / cert-manager ACME challenge "
            "renewal failed silently 14 days ago due to an invalid Route53 DNS validation IAM policy token."
        ),
    ),
    SampleIncident(
        title="Redis Cache Avalanche & Downstream Database Thundering Herd",
        category="Database",
        description=(
            "High Latency Incident: User product catalog page response times degraded from 45ms to 8,200ms. Redis primary cluster "
            "memory usage hit maxmemory policy (volatile-lru) causing mass key evictions. Over 40,000 product cache keys expired "
            "simultaneously with a static TTL of 86400s without jitter. Resulting thundering herd / cache stampede overwhelmed downstream "
            "PostgreSQL read replicas, pushing CPU to 99% and connection wait queues to 25 seconds."
        ),
    ),
    SampleIncident(
        title="Stripe Payment Webhook Signature Mismatch & Order Stoppage",
        category="Third-Party",
        description=(
            "Billing Service Error: 100% of incoming Stripe checkout webhooks returning HTTP 400 Bad Request since 14:30 UTC. "
            "Error logged: 'Invalid signature: Webhook payload timestamp outside tolerance zone or secret mismatch'. Merchant webhook "
            "signing secret 'whsec_...' was rotated in Stripe dashboard during security hygiene rotation, but new secret was not "
            "updated in AWS Secrets Manager or injected into production deployment environment variables."
        ),
    ),
    SampleIncident(
        title="AWS S3 IAM Policy Drift Blocking Document Ingestion Pipeline",
        category="Security",
        description=(
            "Pipeline failure: Automated KYC document ingestion worker failing with 'botocore.exceptions.ClientError: An error "
            "occurred (AccessDenied) when calling the PutObject operation on bucket prod-user-documents-archive'. An automated "
            "Terraform CI pipeline merged an updated Least-Privilege IAM boundary role that inadvertently dropped the 's3:PutObjectTagging' "
            "and 's3:PutObject' permissions for the ingestion-worker-role."
        ),
    ),
    SampleIncident(
        title="Disk Space Exhaustion (100% Storage & Inodes) from Unrotated Debug Logs",
        category="Storage",
        description=(
            "Host Down Alert: Production worker node worker-04.prod stopped responding to health checks. System journal shows "
            "'No space left on device' while writing to /var/log. Filesystem check indicates /dev/nvme0n1p1 mounted on / is at "
            "100% disk utilization and 99.8% inode utilization. Root cause: nginx and custom audit daemon were accidentally set "
            "to log_level=DEBUG during yesterday's profiling session, producing 240GB of uncompressed raw access logs in under 18 hours without logrotate active."
        ),
    ),
]


def get_sample_incidents() -> Dict[str, SampleIncident]:
    """Return dictionary of sample incidents keyed by title."""
    return {inc.title: inc for inc in SAMPLE_INCIDENTS}
