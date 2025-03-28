# NTC-Enigma

This repository contains a Python-based framework to evaluate and modify network traffic datasets (PCAP files) through occlusion techniques and protocol analysis. The framework is based on the research paper:

> **"SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers"**\
> *Nimesha Wickramasinghe, Arash Shaghaghi, Gene Tsudik, Sanjay Jha*\
> *Accepted to IEEE Symposium on Security and Privacy (S&P) - 2025*\
> [Read it on ArXiv](https://arxiv.org/abs/2503.20093)

## 📌 Overview
NTC-Enigma enables a systematic analysis of machine learning-based approaches to network traffic classification (NTC) in the context of modern encryption protocols. It also evaluates the suitability of traffic datasets for NTC, identifies overfitting caused by various design choices, and examines the validity of assumptions underlying NTC models.

## 📂 Repository Structure

```
📁 NTC-Enigma/
├── dataset_evaluation/
│   ├── eval.py
│   ├── id-cipher.csv
│   ├── README.md
│   └── requirements.txt
├── traffic_occlusion/
│   ├── main.py
│   ├── occluder.py
│   ├── README.md
│   └── util.py
│   LICENSE
└── README.md
```

The repository is divided into two main directories:

### [1. dataset_evaluation](https://github.com/nime-sha256/ntc-enigma/tree/main/dataset_evaluation)
This directory contains tools to analyze PCAP files and extract statistics regarding:
- Number of packets, sessions.
- Protocol and cipher suite usage.
- Encryption status (e.g., encrypted or unencrypted traffic).
- Distribution of bulk encryption algorithms.

The results are saved as JSON files for further analysis.

For detailed usage instructions, refer to [dataset_evaluation/README.md](https://github.com/nime-sha256/ntc-enigma/blob/main/dataset_evaluation/README.md).

### [2. traffic_occlusion](https://github.com/nime-sha256/ntc-enigma/tree/main/traffic_occlusion)
This directory provides a set of Python tools to apply occlusion techniques to PCAP files. These techniques mask, modify, or randomize different traffic attributes to protect sensitive information while preserving the structure and properties of the traffic.

For detailed usage instructions, refer to [traffic_occlusion/README.md](https://github.com/nime-sha256/ntc-enigma/blob/main/traffic_occlusion/README.md).

## 🤝 Contribution

Feel free to **fork**, **contribute**, and **open issues** for improvements! For major changes, please open an issue first to discuss your ideas.

## 📜 License

This project is licensed under the **MIT License**.

---

For questions or suggestions, contact:

- **Nimesha Wickramasinghe** - [*n.wickramasinghe@unsw.edu.au*](mailto\:n.wickramasinghe@unsw.edu.au)
- **Arash Shaghaghi** - [*a.shaghaghi@unsw.edu.au*](mailto\:a.shaghaghi@unsw.edu.au)
