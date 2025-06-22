# DARM – DDoS Attack Recognition and Mitigation

DARM is an ONOS (Open Network Operating System) application that enables **real-time detection and mitigation** of DDoS 
attacks in an SDN network. It is based on a **knowledge-aware** architecture, integrating a Kafka pipeline and an 
external intelligent inference engine (ML) to detect malicious behavior, then react automatically by installing blocking 
rules.

---

## Objectives

- **Recognition** of DDoS attacks via an external AI model (local training or pre-trained model)
- **Transmit network metrics** to a Python microservice via Kafka
- **Receive alerts** in real time from the AI engine (Kafka)
- **Automatic** attack mitigation by dynamically injecting ONOS rules (Flow Rules)

---
