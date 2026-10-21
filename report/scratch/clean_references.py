import json
from pathlib import Path

REFS_PATH = Path("report/references.json")

with open(REFS_PATH, "r", encoding="utf-8") as f:
    refs = json.load(f)

# Keys to remove completely
DELETED_KEYS = {
    "urrea2020design",
    "lewandowski2020opcua",
    "happe2021security",
    "alshaer2020automated",
}

# New references to add
NEW_REFS = [
    {
        "key": "modbus2012spec",
        "type": "standard",
        "authors": "Modbus Organization",
        "title": "Modbus Application Protocol Specification V1.1b3",
        "publisher": "Modbus Organization, Inc.",
        "year": 2012,
        "url": "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        "accessed": "2026-10-21"
    },
    {
        "key": "opcfoundation2022spec",
        "type": "standard",
        "authors": "OPC Foundation",
        "title": "OPC Unified Architecture - Part 2: Security Model",
        "publisher": "OPC Foundation",
        "year": 2022,
        "url": "https://opcfoundation.org/developer-tools/specifications-unified-architecture/part-2-security-model/",
        "accessed": "2026-10-21"
    }
]

# Metadata corrections from authority responses
METADATA_UPDATES = {
    "chen2016xgboost": {
        "title": "XGBoost",
        "authors": "T. Chen and C. Guestrin",
        "doi": "10.1145/2939672.2939785",
        "url": "https://doi.org/10.1145/2939672.2939785",
        "year": 2016,
        "booktitle": "Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining"
    },
    "greshake2023not": {
        "title": "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection",
        "authors": "K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz",
        "doi": "10.1145/3605764.3623985",
        "url": "https://doi.org/10.1145/3605764.3623985",
        "year": 2023,
        "booktitle": "Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security"
    },
    "genge2012cyber": {
        "title": "Analyzing Cyber-Physical Attacks on Networked Industrial Control Systems",
        "authors": "B. Genge, I. Nai Fovino, C. Siaterlis, and M. Masera",
        "doi": "10.1007/978-3-642-24864-1_12",
        "url": "https://doi.org/10.1007/978-3-642-24864-1_12",
        "year": 2011,
        "booktitle": "Critical Information Infrastructures Security (CRITIS 2011), Lecture Notes in Computer Science"
    },
    "chandola2009anomaly": {
        "title": "Anomaly detection",
        "authors": "V. Chandola, A. Banerjee, and V. Kumar",
        "year": 2009
    },
    "rfc9293tcp": {
        "title": "Transmission Control Protocol (TCP)",
        "authors": "W. Eddy",
        "type": "standard",
        "year": 2022
    },
    "rfc791ip": {
        "title": "Internet Protocol",
        "authors": "J. Postel",
        "type": "standard",
        "year": 1981
    },
    "islam2019soar": {
        "title": "A Multi-Vocal Review of Security Orchestration, Automation, and Response (SOAR)",
        "authors": "C. Islam, M. A. Babar, and S. Nepal",
        "year": 2019
    },
    "cichonski2012incident": {
        "title": "Computer Security Incident Handling Guide : Recommendations of the National Institute of Standards and Technology",
        "authors": "P. Cichonski, T. Millar, T. Grance, and K. Scarfone",
        "year": 2012
    },
    "hadziosmanovic2014nids": {
        "title": "Through the eye of the PLC: semantic security monitoring for industrial processes",
        "authors": "D. Hadziosmanovic, R. Sommer, E. Zambon, and P. H. Hartel",
        "year": 2014
    },
    "cardenas2011attacks": {
        "title": "Attacks against process control systems: risk assessment, detection, and response",
        "authors": "A. A. Cardenas, S. Amin, Z.-S. Lin, Y.-L. Huang, C.-Y. Huang, and S. Sastry",
        "year": 2011
    },
    "japkowicz2011evaluating": {
        "title": "Evaluating Learning Algorithms: A Classification Perspective",
        "authors": "N. Japkowicz and M. Shah",
        "year": 2011
    },
    "strom2018mitre": {
        "type": "techreport",
        "doi": "",
        "url": "https://www.mitre.org/sites/default/files/publications/pr-18-0944-11-mitre-attack-design-and-philosophy.pdf"
    },
    "shostack2014threat": {
        "type": "book",
        "doi": "",
        "url": "https://www.wiley.com/en-us/Threat+Modeling%3A+Designing+for+Security-p-9781118809990"
    },
    "kaloroumakis2021d3fend": {
        "type": "standard",
        "doi": "",
        "url": "https://d3fend.mitre.org"
    }
}

filtered_refs = []
for entry in refs:
    key = entry.get("key")
    if key in DELETED_KEYS:
        print(f"[-] Removing deleted reference: {key}")
        continue
    if key in METADATA_UPDATES:
        print(f"[~] Updating metadata for: {key}")
        entry.update(METADATA_UPDATES[key])
    filtered_refs.append(entry)

for new_entry in NEW_REFS:
    print(f"[+] Adding verified specification: {new_entry['key']}")
    filtered_refs.append(new_entry)

print(f"Total references after fix: {len(filtered_refs)} (was {len(refs)})")

with open(REFS_PATH, "w", encoding="utf-8") as f:
    json.dump(filtered_refs, f, indent=2, ensure_ascii=False)
print("Updated report/references.json successfully.")
