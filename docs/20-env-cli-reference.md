# Env + CLI Referansi

Bu belge en sik kullanilan environment variable ve CLI bayraklarini teknik gruplara gore listeler.

## 1) Sender ve Dataplane

- `--sender-backend` / `SAMURAI_SENDER_BACKEND`
- `--sender-fallback-policy` / `SAMURAI_SENDER_FALLBACK_POLICY`
- `--xdp-interface` / `SAMURAI_XDP_INTERFACE`
- `--dp-queue-strategy` / `SAMURAI_DP_QUEUE_STRATEGY`
- `--dp-queues`
- `--dp-queue-map`

## 2) Pacing

- `--pacing-mode` (`none|rps|ipg|burst`)
- `--rps`
- `--ipg`
- `--burst-size`
- `--burst-gap`
- `--jitter-model`
- `--jitter-pct`
- `--use-so-txtime`

## 3) GPU Defense / Classifier

- `--gpu-defense-mode` / `SAMURAI_GPU_DEFENSE_MODE`
- `--gpu-classifier-runtime` / `SAMURAI_GPU_CLASSIFIER_RUNTIME`
- `--gpu-classifier-engine-path` / `SAMURAI_GPU_CLASSIFIER_ENGINE_PATH`
- `--gpu-rdma-mode` / `SAMURAI_GPU_RDMA_MODE`
- `--gpu-rdma-strict` / `SAMURAI_GPU_RDMA_STRICT`
- `--gpu-batch-max` / `SAMURAI_GPU_BATCH_MAX`
- `--gpu-batch-flush-timeout-ms` / `SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS`

## 4) GPU RX Pipeline

- `--gpu-rx-pipeline` / `SAMURAI_GPU_RX_PIPELINE`
- `--gpu-rx-iface` / `SAMURAI_GPU_RX_IFACE`
- `--gpu-rx-duration-s` / `SAMURAI_GPU_RX_DURATION_S`
- `--gpu-rx-batch-size` / `SAMURAI_GPU_RX_BATCH_SIZE`
- `--gpu-rx-max-packets` / `SAMURAI_GPU_RX_MAX_PACKETS`
- `--gpu-rx-snaplen` / `SAMURAI_GPU_RX_SNAPLEN`

## 5) Safety

- `--allow-target`
- `--allow-public-target`
- `--safety-global-deny-target`
- `--safety-auto-abort`
- `--disable-safety-auto-abort`

## 6) Distributed Control Plane

- `--role master|slave|standalone`
- `--control-listen`
- `--control-endpoints`
- `--cluster-secret` / `SAMURAI_CLUSTER_SECRET`
- `--control-insecure`
- `--control-tls-cert`, `--control-tls-key`, `--control-tls-ca`
- `--control-tls-client-cert`, `--control-tls-client-key`, `--control-tls-client-ca`
- `--control-require-client-auth`

## 7) Management API Auth

- `--management-api-enable`
- `--management-api-listen`
- `--management-api-auth-token`
- `--management-api-admin-token`
- `--management-api-operator-token`
- `--management-api-viewer-token`
- `--management-api-jwt-secret`
- `--management-api-jwt-role-claim`
- `--management-api-jwt-tenant-claim`
- `--management-api-trusted-identity-secret`
- `--management-api-trusted-identity-secret-header`
- `--management-api-trusted-identity-role-header`
- `--management-api-trusted-identity-tenant-header`

## 8) HA ve Multi-Master

- `--ha-enable`
- `--ha-mode` (`static|file-lock|redis|etcd|raft`)
- `--ha-*` lease/election parametreleri
- `--multi-master-enable`
- `--multi-master-region-id`
- `--multi-master-redis-url`
- `--multi-master-namespace`

## 9) Lisans

- `--license-key`
- `--license-file`
- `--license-activate`
- `--license-deactivate`
- `--license-info`
- `--license-account`
- `--license-trial`
- `SAMURAI_LICENSE_KEY`

## 10) Raporlama

- `--run-report`
- `--run-report-format` (`json|md|both`)
- `--run-report-out`
- `--run-report-dir`
- `--prom-textfile`

Detayli acceptance ve benchmark icin bkz:
- `docs/23-benchmark-acceptance-handbook.md`
- `docs/24-enterprise-test-scenarios-handbook.md`
