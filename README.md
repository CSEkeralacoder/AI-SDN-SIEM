
# 🔐 AI-SDN-SIEM
### An AI‑Driven SIEM Framework for Software‑Defined Networks with Automated Mitigation

---

## 📌 Overview

AI-SDN-SIEM is a **lightweight, AI‑driven Security Information and Event Management (SIEM) framework** designed for **Software‑Defined Networks (SDN)**.  
The system integrates **deep learning–based intrusion detection**, **SDN programmability**, and **real‑time SIEM analytics** to detect and mitigate network attacks automatically.

A **CNN‑BiLSTM model** is used to analyze **spatial and temporal flow features**, while the SDN controller enforces mitigation actions using **OpenFlow rules**. Security events are logged and visualized using **OpenSearch Dashboards**.

---

## 🎯 Objectives

- Detect network attacks in SDN environments using **AI‑based traffic analysis**
- Reduce false positives compared to rule‑based SIEM systems
- Enable **real‑time automated mitigation**
- Provide **SIEM‑style visibility and analytics**
- Maintain a **lightweight, modular, and scalable architecture**

---

## 🧠 System Architecture

The system consists of four tightly integrated layers:

1. **Traffic Emulation Layer**
   - Mininet is used to generate normal and attack traffic

2. **SDN Control Layer**
   - Ryu SDN Controller
   - Collects OpenFlow flow statistics
   - Installs forwarding and mitigation rules dynamically

3. **AI Detection Layer**
   - CNN‑BiLSTM model (TensorFlow Lite)
   - Classifies traffic as *Normal* or *Attack*
   - Generates confidence scores and attack reasons

4. **SIEM & Visualization Layer**
   - Fluent Bit for log ingestion
   - OpenSearch for indexing
   - OpenSearch Dashboards for visualization

---

## 🧩 Project Structure

AI-SDN-SIEM/
├── sdn-service/
│ ├── controllers/
│ │ ├── primary_controller.py
│ │ └── security_controller.py
│ ├── ai-service/
│ │ ├── app.py
│ │ ├── feature_extractor.py
│ │ └── models/
│ ├── docker-compose.yml
│ ├── Dockerfile
│ └── start_ryu.sh
│
├── siem-docker-v1/
│ ├── docker-compose.yml
│ └── fluent-bit.conf
│
├── README.md
└── .gitignore 

---

## ⚙️ Technologies Used

- **SDN Controller:** Ryu (OpenFlow)
- **AI Model:** CNN‑BiLSTM
- **Inference Engine:** TensorFlow Lite
- **Backend:** Flask (REST API)
- **SIEM Stack:** Fluent Bit + OpenSearch
- **Visualization:** OpenSearch Dashboards
- **Deployment:** Docker & Docker Compose
- **Traffic Generator:** Mininet

---

## 🛡️ Attack Scenarios Evaluated

- ICMP Flood (DoS)
- TCP SYN Flood
- Malicious Flow Patterns
- Normal ICMP and TCP traffic (baseline)

---

## 🔄 System Workflow

1. Traffic flows through OpenFlow switches
2. Ryu controller collects flow‑level statistics
3. Features are extracted and normalized
4. CNN‑BiLSTM performs attack classification
5. If an attack is detected:
   - OpenFlow DROP rules are installed automatically
   - Security events are generated
6. Logs are ingested into OpenSearch
7. Dashboards visualize attacks in real time

---

## 📊 SIEM Dashboard Capabilities

- Attack type distribution
- Severity‑based categorization
- Temporal attack trends
- Source IP‑based filtering
- Real‑time SOC‑style monitoring

---

## 🧪 Experimental Setup

- **Environment:** Docker‑based microservices
- **Controller:** Ryu SDN Controller
- **Traffic:** Mininet emulation
- **Evaluation Metrics:** Detection accuracy, response time, false positives

---

## 📈 Key Results & Observations

- Accurate detection of DoS and flooding attacks
- Very low false positives for normal traffic
- Near real‑time automated mitigation
- Lightweight deployment suitable for SDN environments
- Improved visibility through SIEM dashboards

---

## ▶️ How to Run (High‑Level)

1. Start the SIEM stack (`siem-docker-v1`)
2. Start the SDN services (`sdn-service`)
3. Launch the Mininet topology
4. Generate normal and attack traffic
5. Monitor alerts in OpenSearch Dashboards

*(Detailed commands can be added if required)*

---

## 🎓 Academic Relevance

This project demonstrates:
- Practical integration of **AI + SDN + SIEM**
- Application of **CNN‑BiLSTM for network security**
- Automated mitigation using **programmable networks**
- Real‑world SOC‑style security analytics

---

## 🔮 Future Enhancements

- Explainable AI (XAI) for alert justification
- Multi‑controller SDN environments
- Online and adaptive learning
- Additional attack classes
- Policy‑driven mitigation strategies

---

## 👨‍💻 Author

Vishnu P U

---

## 🏷️ Keywords

**SDN, SIEM, CNN‑BiLSTM, Intrusion Detection, Cybersecurity, OpenSearch**
