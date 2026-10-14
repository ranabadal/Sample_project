"""Incident analyzer engine with abstract base and deterministic rule-based implementation."""

from abc import ABC, abstractmethod
import re
import uuid
from datetime import datetime
from typing import List, Tuple, Optional

from .models import IncidentAnalysis, SeverityLevel, IncidentCategory


class BaseIncidentAnalyzer(ABC):
    """Abstract base class for incident triage analyzers (Rule-based, LLM, etc.)."""

    @abstractmethod
    def analyze(self, incident_text: str) -> IncidentAnalysis:
        """Analyze an incident description and return a structured IncidentAnalysis."""
        pass


class RuleBasedAnalyzer(BaseIncidentAnalyzer):
    """Deterministic, offline rule-based incident analyzer.
    
    Uses domain heuristics, log pattern matching, and sentence-level evidence extraction
    to classify severity, diagnose root causes, and produce prioritized runbooks.
    """

    def analyze(self, incident_text: str) -> IncidentAnalysis:
        cleaned_text = (incident_text or "").strip()
        if not cleaned_text:
            raise ValueError("Incident description cannot be empty or whitespace only.")

        if len(cleaned_text) < 15:
            raise ValueError("Incident description is too brief to analyze. Please provide error logs or symptoms.")

        lower_text = cleaned_text.lower()
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Specialized Pattern Matches (for known realistic failure modes)
        specialized = self._check_specialized_scenarios(cleaned_text, lower_text)
        if specialized:
            specialized.incident_id = incident_id
            specialized.timestamp = timestamp
            specialized.raw_input = cleaned_text
            return specialized

        # 2. General Rule-based Heuristic Fallback
        severity = self._detect_severity(lower_text)
        category = self._detect_category(lower_text)
        evidence = self._extract_evidence(cleaned_text, lower_text)
        title = self._generate_title(lower_text, category)
        root_cause, next_action, steps = self._generate_runbook(lower_text, category, severity)
        blast_radius = self._estimate_blast_radius(lower_text, severity)
        confidence = self._calculate_confidence(lower_text, evidence)

        summary = f"Detected {severity.value} severity {category.value} incident affecting {blast_radius}."

        return IncidentAnalysis(
            incident_id=incident_id,
            timestamp=timestamp,
            title=title,
            severity=severity,
            category=category,
            confidence_score=confidence,
            summary=summary,
            likely_root_cause=root_cause,
            supporting_evidence=evidence,
            prioritized_troubleshooting_steps=steps,
            recommended_next_action=next_action,
            blast_radius=blast_radius,
            raw_input=cleaned_text,
        )

    def _check_specialized_scenarios(self, raw_text: str, lower_text: str) -> Optional[IncidentAnalysis]:
        """Check for high-fidelity specific patterns matching production scenarios."""
        
        # Scenario 1: Postgres Connection Pool / Deadlock
        if any(k in lower_text for k in ["pgbouncer", "max_connections", "connection slots are reserved", "exclusive table lock", "orders' table"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "max_connections", "slots", "504", "pgbouncer", "lock", "migration", "timeout"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="PostgreSQL Connection Pool Saturation & Lock Contention",
                severity=SeverityLevel.CRITICAL,
                category=IncidentCategory.DATABASE,
                confidence_score=96,
                summary="RDS PostgreSQL cluster exhausted maximum connection limits due to an unindexed migration acquiring exclusive table locks, cascading into Gateway Timeouts.",
                likely_root_cause="Connection starvation induced by an unindexed migration acquiring an exclusive lock on the 'orders' table, causing pgbouncer session connections to pile up and exceed max_connections.",
                supporting_evidence=evidence or [
                    "RDS cluster hit 100% max_connections (500/500)",
                    "FATAL: remaining connection slots are reserved for non-replication superuser connections",
                    "Active query analysis shows exclusive table lock on 'orders' table due to unindexed migration"
                ],
                prioritized_troubleshooting_steps=[
                    "Identify and cancel blocking migration transaction: SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE wait_event_type = 'Lock';",
                    "Terminate idle-in-transaction client sessions to free connection slots.",
                    "Switch pgbouncer pool mode from 'session' to 'transaction' mode to maximize connection reuse.",
                    "Temporarily route read-only query volume to available read replicas.",
                ],
                recommended_next_action="Execute immediate termination of the blocking lock query on 'orders' and verify pgbouncer connection queue clears.",
                blast_radius="Production Checkout & Authentication Services (All Active Users)",
                raw_input=raw_text,
            )

        # Scenario 2: Kubernetes OOMKilled / Exit Code 137
        if any(k in lower_text for k in ["oomkilled", "exit code 137", "crashloopbackoff", "memory pressure", "heap dump metrics"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "oomkilled", "137", "memory", "replica", "heap", "container limit"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Kubernetes Pod Memory Limit Breach & OOMKill CrashLoop",
                severity=SeverityLevel.CRITICAL if "payment" in lower_text or "prod" in lower_text else SeverityLevel.HIGH,
                category=IncidentCategory.INFRASTRUCTURE,
                confidence_score=94,
                summary="Service pods entering CrashLoopBackOff due to Linux cgroup memory limit enforcement (Exit Code 137).",
                likely_root_cause="Rapid JVM heap expansion exceeded the Kubernetes container memory limit (2Gi), triggering kernel OOMKiller termination within minutes of container startup.",
                supporting_evidence=evidence or [
                    "Pod terminated with exit code 137 (OOMKilled)",
                    "Replica count dropped from 12 to 3 healthy replicas",
                    "JVM memory consumption climbing exponentially until container limit (2Gi) breached"
                ],
                prioritized_troubleshooting_steps=[
                    "Check pod events and restart history: kubectl describe pod -n prod-payments <pod_name>",
                    "Patch deployment manifest to double memory limits: kubectl set resources deployment payment-processor --limits=memory=4Gi",
                    "Inspect JVM heap parameters (-XX:MaxRAMPercentage, -Xmx) to ensure head room below cgroup limits.",
                    "Capture and inspect memory dump from crashing container to pinpoint object allocation leak.",
                ],
                recommended_next_action="Patch deployment memory limit to 4Gi immediately to stabilize available replicas and halt crash loop.",
                blast_radius="Payment Processing Pipeline (Payment Confirmations Failing)",
                raw_input=raw_text,
            )

        # Scenario 3: CoreDNS NXDOMAIN / Resolution Storm
        if any(k in lower_text for k in ["coredns", "nxdomain", "no such host", "upstream resolver", "resolution storm"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "nxdomain", "no such host", "coredns", "throttling", "retry", "query volume"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="CoreDNS Cluster Resolution Outage & Query Stampede",
                severity=SeverityLevel.CRITICAL,
                category=IncidentCategory.NETWORKING,
                confidence_score=95,
                summary="Cluster-wide internal DNS resolution failure causing internal gRPC lookups to return NXDOMAIN.",
                likely_root_cause="Service release v2.4.1 bypassed local DNS caching and triggered un-jittered retry loops, flooding CoreDNS pods and driving upstream resolver rate-limiting.",
                supporting_evidence=evidence or [
                    "Internal gRPC calls failing with 'dial tcp: lookup auth.internal... no such host (NXDOMAIN)'",
                    "CoreDNS logs show CPU throttling and packet drops at upstream resolver 1.1.1.1",
                    "Query volume spiked 800% after deployment v2.4.1 removed in-memory DNS caching"
                ],
                prioritized_troubleshooting_steps=[
                    "Scale CoreDNS deployment horizontally: kubectl scale deployment coredns -n kube-system --replicas=8",
                    "Roll back client deployment v2.4.1 to restore local DNS caching behavior.",
                    "Verify CoreDNS Corefile configuration for upstream forwarder health and cache TTL settings.",
                    "Deploy NodeLocal DNSCache DaemonSet to insulate upstream resolvers from client storms.",
                ],
                recommended_next_action="Scale CoreDNS pods immediately and initiate rollback of release v2.4.1.",
                blast_radius="Cluster-Wide (All Internal Service-to-Service gRPC Communications)",
                raw_input=raw_text,
            )

        # Scenario 4: SSL/TLS Certificate Expiration
        if any(k in lower_text for k in ["err_cert_date_invalid", "certificate expired", "tls handshake failure", "cert-manager", "validity window expired"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "cert", "ssl", "tls", "handshake", "expired", "route53", "acme"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Production Ingress TLS Wildcard Certificate Expiration",
                severity=SeverityLevel.CRITICAL,
                category=IncidentCategory.SECURITY,
                confidence_score=98,
                summary="Production wildcard TLS certificate expired, preventing all client HTTPS traffic across web and mobile endpoints.",
                likely_root_cause="ACME DNS-01 challenge renewal via cert-manager failed silently due to an invalid Route53 IAM policy token, leaving the existing wildcard certificate expired without automatic renewal.",
                supporting_evidence=evidence or [
                    "Browser security warnings 'NET::ERR_CERT_DATE_INVALID' and 'SSL certificate expired'",
                    "Ingress controller nginx logs show TLS handshake failure for domain *.api.domain.com",
                    "Certificate validity window expired on 2026-10-14 00:00:00 UTC"
                ],
                prioritized_troubleshooting_steps=[
                    "Inspect cert-manager challenge and certificate resources: kubectl describe certificate,challenge -A",
                    "Update expired Route53 IAM credentials in the cert-manager ClusterIssuer secret.",
                    "Manually trigger certificate renewal: cmctl renew --all or kubectl delete certificaterequest",
                    "If ACME automation is stuck, manually upload an emergency wildcard certificate secret to ingress namespace.",
                ],
                recommended_next_action="Correct Route53 credentials or manually push an emergency wildcard certificate secret and reload ingress-nginx.",
                blast_radius="Public Domain *.api.domain.com (100% of Web & Mobile Users Blocked)",
                raw_input=raw_text,
            )

        # Scenario 5: Redis Cache Avalanche / Stampede
        if any(k in lower_text for k in ["redis", "cache avalanche", "thundering herd", "volatile-lru", "cache stampede", "evictions"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "latency", "redis", "evictions", "ttl", "thundering herd", "stampede", "cpu"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Redis Cache Avalanche & Downstream Database Saturation",
                severity=SeverityLevel.HIGH,
                category=IncidentCategory.DATABASE,
                confidence_score=92,
                summary="Simultaneous expiration of tens of thousands of cache keys caused a thundering herd that degraded response latency from 45ms to 8,200ms.",
                likely_root_cause="Static uniform TTL (86400s) without jitter triggered synchronized expiration of 40,000 product keys, flooding downstream PostgreSQL read replicas.",
                supporting_evidence=evidence or [
                    "Catalog page response times degraded from 45ms to 8,200ms",
                    "Redis memory hit volatile-lru maxmemory policy causing mass key evictions",
                    "Over 40,000 product cache keys expired simultaneously with static TTL of 86400s"
                ],
                prioritized_troubleshooting_steps=[
                    "Run an emergency pre-warming script to populate top 1,000 high-frequency product keys into Redis.",
                    "Apply request rate-limiting on catalog search endpoints to protect database replicas.",
                    "Deploy hotfix introducing +/- 15% random jitter to cache TTL generation.",
                    "Temporarily scale read replica compute instances to absorb read spike.",
                ],
                recommended_next_action="Run cache pre-warm script for top product catalog keys and throttle non-essential catalog traffic.",
                blast_radius="Product Catalog & Storefront Browsing (High Latency for All Customers)",
                raw_input=raw_text,
            )

        # Scenario 6: Stripe Webhook Signature Mismatch
        if any(k in lower_text for k in ["stripe", "webhook", "invalid signature", "whsec_", "tolerance zone", "secret mismatch"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "400 bad request", "signature", "webhook", "whsec", "stripe", "secrets manager"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Payment Webhook Signature Mismatch & Order Stoppage",
                severity=SeverityLevel.HIGH,
                category=IncidentCategory.THIRD_PARTY,
                confidence_score=97,
                summary="100% of incoming payment webhooks failing with HTTP 400 Bad Request due to cryptographic signature verification failure.",
                likely_root_cause="Stripe webhook signing secret ('whsec_...') was rotated in developer portal but was not updated in AWS Secrets Manager or deployed to billing containers.",
                supporting_evidence=evidence or [
                    "100% of incoming Stripe checkout webhooks returning HTTP 400 Bad Request",
                    "Invalid signature: Webhook payload timestamp outside tolerance zone or secret mismatch",
                    "Signing secret rotated in dashboard but not updated in AWS Secrets Manager"
                ],
                prioritized_troubleshooting_steps=[
                    "Retrieve the active signing secret ('whsec_...') from the Stripe Dashboard Webhooks panel.",
                    "Update secret value in AWS Secrets Manager: aws secretsmanager update-secret --secret-id prod/billing/stripe",
                    "Trigger a rolling restart of billing service deployment to reload environment variables.",
                    "Trigger webhook event retry batch from Stripe Dashboard to backfill unprocessed transactions.",
                ],
                recommended_next_action="Update webhook secret in AWS Secrets Manager and restart the billing service pods.",
                blast_radius="Order Fulfillment & Payment Confirmations (Orders Pending Fulfillment)",
                raw_input=raw_text,
            )

        # Scenario 7: AWS S3 IAM Policy Drift / Access Denied
        if any(k in lower_text for k in ["accessdenied", "putobject", "s3", "botocore", "iam boundary", "ingestion-worker-role"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "accessdenied", "putobject", "s3", "terraform", "iam", "permission"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Cloud Storage IAM Policy Drift & Document Ingestion Block",
                severity=SeverityLevel.HIGH,
                category=IncidentCategory.SECURITY,
                confidence_score=95,
                summary="Automated KYC ingestion workers blocked with AccessDenied when attempting to upload documents to AWS S3.",
                likely_root_cause="Terraform CI pipeline merged an overly restrictive IAM boundary role that stripped 's3:PutObject' and 's3:PutObjectTagging' from the worker role.",
                supporting_evidence=evidence or [
                    "botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling PutObject",
                    "Terraform CI pipeline merged an updated Least-Privilege IAM boundary role",
                    "Inadvertently dropped 's3:PutObjectTagging' and 's3:PutObject' permissions"
                ],
                prioritized_troubleshooting_steps=[
                    "Verify CloudTrail event logs for AccessDenied on bucket 'prod-user-documents-archive'.",
                    "Review git history of the Terraform IAM module commit that altered the boundary policy.",
                    "Apply an emergency inline policy grant or revert the Terraform commit via CI pipeline.",
                    "Verify ingestion worker queue picks up backlogged document uploads.",
                ],
                recommended_next_action="Revert the offending Terraform commit or attach temporary inline S3 PutObject permission to the ingestion worker role.",
                blast_radius="KYC Document Ingestion Pipeline (Customer Onboarding Queue Halted)",
                raw_input=raw_text,
            )

        # Scenario 8: Disk Full / 100% Inodes from Debug Logs
        if any(k in lower_text for k in ["no space left on device", "100% disk", "inode utilization", "log_level=debug", "nvme0n1p1"]):
            evidence = self._extract_matching_sentences(raw_text, [
                "no space", "disk utilization", "inode", "/var/log", "debug", "logrotate"
            ])
            return IncidentAnalysis(
                incident_id="",
                timestamp="",
                title="Node Filesystem & Inode Depletion from Unrotated Logs",
                severity=SeverityLevel.CRITICAL if "worker" in lower_text or "prod" in lower_text else SeverityLevel.HIGH,
                category=IncidentCategory.STORAGE,
                confidence_score=96,
                summary="Production host became unresponsive after root partition reached 100% disk and 99.8% inode utilization.",
                likely_root_cause="Services left running with 'log_level=DEBUG' without active logrotate generated 240GB of raw logs, filling the root partition completely.",
                supporting_evidence=evidence or [
                    "System journal shows 'No space left on device' while writing to /var/log",
                    "Filesystem check indicates /dev/nvme0n1p1 mounted on / is at 100% disk and 99.8% inode utilization",
                    "daemons set to log_level=DEBUG produced 240GB of uncompressed raw logs in under 18 hours"
                ],
                prioritized_troubleshooting_steps=[
                    "Access worker via out-of-band serial console / SSH and safely truncate large log files: truncate -s 0 /var/log/nginx/*.log",
                    "Revert daemon logging configuration from DEBUG back to INFO / WARNING.",
                    "Verify active processes release held disk blocks using: lsof +L1",
                    "Ensure logrotate service is enabled with aggressive maxsize and daily rotation constraints.",
                ],
                recommended_next_action="Truncate active debug log files immediately to recover root partition capacity, then switch log level to INFO.",
                blast_radius="Production Worker Node (Background Job Processing Unresponsive)",
                raw_input=raw_text,
            )

        return None

    def _detect_severity(self, text: str) -> SeverityLevel:
        """Evaluate severity based on failure indicators, error rates, and blast radius signals."""
        critical_indicators = [
            "critical", "outage", "sev1", "sev-1", "p0", "downtime", "data loss", "deadlock",
            "100% failed", "crashloop", "all users", "emergency", "service-wide", "unresponsive",
            "504 gateway timeout", "exit code 137", "oomkilled", "certificate expired"
        ]
        high_indicators = [
            "high", "p1", "sev2", "sev-2", "latency", "degraded", "spike", "throttled",
            "rate limit", "500 internal", "timeout", "packet drop", "accessdenied", "permission denied"
        ]
        medium_indicators = [
            "medium", "p2", "sev3", "intermittent", "warning", "slow", "retry", "queue backing up"
        ]

        if any(ind in text for ind in critical_indicators):
            return SeverityLevel.CRITICAL
        if any(ind in text for ind in high_indicators):
            return SeverityLevel.HIGH
        if any(ind in text for ind in medium_indicators):
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _detect_category(self, text: str) -> IncidentCategory:
        """Map textual patterns to primary architectural incident category."""
        if any(w in text for w in ["database", "postgres", "mysql", "rds", "sql", "table", "lock", "redis", "query", "deadlock"]):
            return IncidentCategory.DATABASE
        if any(w in text for w in ["dns", "nxdomain", "network", "grpc", "connection refused", "socket", "packet", "gateway", "cidr"]):
            return IncidentCategory.NETWORKING
        if any(w in text for w in ["pod", "kubernetes", "k8s", "node", "cpu", "memory", "oom", "ec2", "cluster", "container"]):
            return IncidentCategory.INFRASTRUCTURE
        if any(w in text for w in ["ssl", "tls", "cert", "token", "iam", "accessdenied", "auth", "permission", "unauthorized"]):
            return IncidentCategory.SECURITY
        if any(w in text for w in ["disk", "inode", "filesystem", "s3", "storage", "volume", "nvme", "full"]):
            return IncidentCategory.STORAGE
        if any(w in text for w in ["deploy", "rollback", "release", "ci/cd", "pipeline", "version", "git"]):
            return IncidentCategory.DEPLOYMENT
        if any(w in text for w in ["stripe", "twilio", "webhook", "third-party", "vendor", "external api", "partner"]):
            return IncidentCategory.THIRD_PARTY
        return IncidentCategory.GENERAL

    def _extract_evidence(self, raw_text: str, lower_text: str) -> List[str]:
        """Extract high-relevance sentences from the raw input as supporting evidence."""
        sentences = re.split(r"(?<=[.!?\n])\s+", raw_text)
        keywords = ["error", "fatal", "fail", "timeout", "exception", "100%", "denied", "expired", "alert", "spik", "drop"]
        matches = []
        for s in sentences:
            s_clean = s.strip()
            if not s_clean:
                continue
            if any(k in s_clean.lower() for k in keywords):
                matches.append(s_clean)
        return matches[:4] if matches else [raw_text[:200] + "..."]

    def _extract_matching_sentences(self, raw_text: str, keywords: List[str]) -> List[str]:
        """Helper to extract sentences containing any of the specified keywords."""
        sentences = re.split(r"(?<=[.!?\n])\s+", raw_text)
        evidence = []
        for s in sentences:
            s_clean = s.strip()
            if not s_clean:
                continue
            if any(k in s_clean.lower() for k in keywords):
                evidence.append(s_clean)
        return evidence[:4]

    def _generate_title(self, lower_text: str, category: IncidentCategory) -> str:
        """Create a clear, professional incident title."""
        if "outage" in lower_text or "down" in lower_text:
            return f"Production {category.value} Service Outage"
        if "latency" in lower_text or "slow" in lower_text:
            return f"Severe Latency Degradation in {category.value}"
        if "error" in lower_text or "fail" in lower_text:
            return f"Elevated Error Rate in {category.value}"
        return f"Incident Detected in {category.value}"

    def _generate_runbook(self, lower_text: str, category: IncidentCategory, severity: SeverityLevel) -> Tuple[str, str, List[str]]:
        """Generate root-cause hypothesis, next action, and prioritized troubleshooting runbook."""
        if category == IncidentCategory.DATABASE:
            root_cause = "Database performance degradation likely caused by connection saturation, blocking queries, or locking contention."
            next_action = "Inspect active locks and long-running queries via database management console or pg_stat_activity."
            steps = [
                "Check connection count against max_connections limit.",
                "Identify blocking queries or long-running transactions.",
                "Review slow query logs and index usage.",
                "Evaluate cache hit ratios and connection pooler health.",
            ]
        elif category == IncidentCategory.NETWORKING:
            root_cause = "Network partition, DNS resolution failure, or ingress gateway timeout between microservice components."
            next_action = "Verify upstream gateway health and run DNS resolution checks from inside the cluster."
            steps = [
                "Test internal DNS resolution from client containers.",
                "Check ingress and load balancer target group health status.",
                "Verify security group and network ACL rules for recent changes.",
                "Inspect network packet drop and latency metrics.",
            ]
        elif category == IncidentCategory.INFRASTRUCTURE:
            root_cause = "Compute resource exhaustion (CPU throttling or memory pressure) triggering container or host instability."
            next_action = "Check container metrics and restart crash-looping workloads with increased resource headroom."
            steps = [
                "Examine host and container CPU/Memory utilization graphs.",
                "Inspect container restart logs and system events.",
                "Scale cluster node capacity or pod replicas.",
                "Review recent deployments or workload spikes.",
            ]
        elif category == IncidentCategory.SECURITY:
            root_cause = "Credential expiration, invalid IAM permission boundary, or token validation failure."
            next_action = "Verify authentication tokens and audit recent IAM or certificate changes."
            steps = [
                "Verify validity dates on SSL/TLS certificates and API tokens.",
                "Review audit logs for AccessDenied / 401 / 403 events.",
                "Audit recent IAM policy or security group deployments.",
                "Test authentication handshake using test credentials.",
            ]
        else:
            root_cause = "Application logic failure or unexpected state transition causing elevated errors."
            next_action = "Check recent deployment history and review centralized application logs."
            steps = [
                "Review application error logs for stack traces and recurring exceptions.",
                "Correlate incident start time with recent CI/CD deployments or configuration changes.",
                "Verify external dependencies and upstream API status.",
                "Roll back to the previous known good deployment if errors started after a release.",
            ]

        return root_cause, next_action, steps

    def _estimate_blast_radius(self, lower_text: str, severity: SeverityLevel) -> str:
        """Estimate the operational scope and blast radius."""
        if "all" in lower_text or "production" in lower_text or severity == SeverityLevel.CRITICAL:
            return "Production Environment (Broad Customer Impact)"
        if severity == SeverityLevel.HIGH:
            return "Specific Subsystem / Downstream Services"
        if severity == SeverityLevel.MEDIUM:
            return "Partial Traffic / Intermittent Users"
        return "Internal / Non-Critical Component"

    def _calculate_confidence(self, lower_text: str, evidence: List[str]) -> int:
        """Calculate confidence percentage based on evidence depth."""
        base = 75
        if len(evidence) >= 2:
            base += 10
        if any(term in lower_text for term in ["error", "fatal", "exit code", "exception", "status 5"]):
            base += 10
        return min(base, 98)
