# eks-ai-remediation-app

| Component | Purpose |
|---|---|
| `orders-api/` | Demo service the agent watches (stdlib Python; two demo failure modes) |
| `orders-runbook-mcp/` | MCP server: CloudWatch Logs Insights + metrics, ECR tags, and `propose_fix` (opens a PR). Untrusted log text is screened by a Bedrock Guardrail |
| `alert-bridge/` | Pulls CloudWatch alarm events from SQS inside the cluster and starts the agent over A2A |

CI (`.github/workflows/ci.yml`) builds changed components, pushes to ECR with
GitHub OIDC, and commits the new image tag to the config repo. It never touches
the cluster: Argo CD pulls the change.
