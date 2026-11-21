AEGIS DEMONSTRATION EVIDENCE BUNDLE
===================================

Scenario:
A fictional e-commerce microservice application experiences intermittent order
creation failures on 14 October 2026 between approximately 10:04 and 10:12 UTC.

Files:
1. application_logs.json
   Combined INFO, WARN and ERROR application events. Includes successful
   requests as well as failed requests.

2. system_metrics.csv
   Time-series metrics for order-service, payment-service and api-gateway.

3. distributed_traces.json
   Example distributed request traces for successful and failed order requests.

4. deployment_changes.csv
   Recent deployment/configuration events. One configuration change reduces
   the Order Service database connection pool maximum from 30 to 5 shortly
   before failures begin.

Expected investigation direction (not a guaranteed answer):
The evidence is designed to support investigating a possible relationship
between the reduced database connection pool, connection pool exhaustion,
and Order Service request failures. The system should verify evidence before
presenting this as a supported hypothesis.

Important:
These are synthetic, fictional demonstration records created for the AEGIS
prototype. They are not taken from RCAEval or a real production application.
Do not describe them as real-world measured data in the report.
