FROM python:3.12-slim
WORKDIR /lab
COPY scripts/simulate_traffic.py scripts/e2e_detection_check.py ./
COPY siem/detection_rules ./siem/detection_rules
USER 1000
CMD ["python", "simulate_traffic.py"]
