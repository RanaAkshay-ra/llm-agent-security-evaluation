# Security Evaluation of LLM-Based Autonomous Agents

## Overview

This repository contains the source code developed for the MSc Cyber Security dissertation titled:

**Security Evaluation of LLM-Based Autonomous Agents: Mapping Tool-Use Behaviours to MITRE ATT&CK**

The project presents a secure experimental framework for evaluating the behaviour of Large Language Model (LLM)-based autonomous agents operating within a controlled Docker sandbox.

---

## Research Objectives

The project aims to:

- Evaluate autonomous AI agent behaviour.
- Analyse security-related tool usage.
- Record behavioural execution logs.
- Map observed behaviours to MITRE ATT&CK.
- Investigate AI-specific threats using MITRE ATLAS.
- Produce a reproducible experimental framework.

---

## Technologies Used

- Python
- LangChain
- Ollama
- Docker
- Ubuntu Linux
- JSON
- MITRE ATT&CK
- MITRE ATLAS

---

## Repository Structure

```text
llm-agent-security-evaluation/
│
├── agents/
├── archive/
├── docs/
├── scenarios/
│
├── analyse_dataset.py
├── experiment_runner.py
├── main.py
├── master_dataset.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Experimental Scenarios

- Scenario 01 – File Discovery
- Scenario 02 – Command Execution
- Scenario 03 – System Information Discovery
- Scenario 04 – Secure API Interaction
- Scenario 05 – Prompt Injection

---

## How to Run

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the project:

```bash
python experiment_runner.py
```

---

## Author

Akshaykumar Shitalkumar Rana

MSc Cyber Security

University of Roehampton

2026
