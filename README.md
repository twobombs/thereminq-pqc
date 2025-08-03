# ThereminQ-PQC

![Gemini_Generated_Image_wt29dqwt29dqwt29_1_50_1_50](https://github.com/user-attachments/assets/d9f55041-7723-49e3-b693-389e4f373b0e)

inspired from this [X post](https://x.com/twobombs/status/1873662745377435856)
## PQC applications with Quantum (inspired) PoC

This repository represents an effort to gather containerized PQC applications together in one place with their Quantum (inspired) PoC

Note: because of Ising breakthroughs and related benchmarking QFT related algos are moved to the 2026 timetable

### PQC applications are
- [NginX](https://github.com/twobombs/thereminq-pqc/blob/main/Dockerfile-nginx)
- [SSH](https://github.com/twobombs/thereminq-pqc/blob/main/Dockerfile-ssh)

### Roadmap: late 2025/2026+
- Clustering of PoC appliances
- Data driven & middleware
- Agentic PQC scans
- AI MCP functionality
- BTC-SHA analysis

### Quantum (Inspired) PoCs are
- [Qimcifa](https://github.com/vm6502q/qimcifa) inspired [FindAfactor](https://github.com/vm6502q/FindAFactor)
```bash
docker run [--cpus=12 --cpuset-cpus=0-11 --cpuset-mems=0 -m 8192m] twobombs/thereminq-pqc:findafactor
````
findafactor is NUMA sensitive; we recommend binding every instance to a NUMA cluster of cpu threads per docker and system specifications

- [Shors'](https://github.com/twobombs/thereminq-tensors/tree/master?tab=readme-ov-file#shors-rsa-ssh-keypair-factorization-and-2-primes-test-loop)

Container images will be delivered experimentally HPC ready and/or with ThereminQ WebUI

