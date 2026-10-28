# LinkArmor: System Architecture & Feature Engineering Pipeline

## System Overview
LinkArmor is an enterprise-grade Machine Learning system designed for real-time malicious, phishing, and malware URL detection. It evaluates lexical, structural, and domain-level heuristics without relying solely on static blacklists.

```
       Incoming Target URL
               |
               v
   [ Lexical & Structural Parser ]
   Extracts 27 Statistical Features
               |
               v
    [ Feature Vector Standardization ]
               |
               v
   [ Ensemble Model Evaluation ]
 +-------------+-------------+
 |                           |
 v                           v
Random Forest Classifier   XGBoost Gradient Boosting
 |                           |
 +-------------+-------------+
               |
               v
      [ Soft-Voting Blender ]
               |
               v
  Threat Probability Score (0.00 - 1.00)
    Classification: [ BENIGN / MALICIOUS ]
```

## Feature Extraction Matrix (27 Lexical & Structural Metrics)
LinkArmor analyzes URL properties across three primary dimensions:

### 1. Structural & Syntactic Properties
* **Total URL Length:** Malicious URLs often embed query redirections or obfuscated tokens.
* **Domain & Path Length:** Disproportionate path-to-domain ratios.
* **Dot Count (`.`):** Excessive subdomains designed to mimic legitimate institutions.
* **Special Character Density:** Frequencies of `@`, `-`, `_`, `=`, `?`, `%`, `&`, `#`.
* **Digit-to-Letter Ratio:** High entropy character distributions in resource paths.

### 2. Lexical & Obfuscation Heuristics
* **IP Address in Hostname:** Direct IPv4/IPv6 indicators circumventing DNS registries.
* **Security Protocol Analysis:** Protocol scheme validation (`http://` vs. `https://`).
* **Shortening Service Signatures:** Flags known redirection hubs (`bit.ly`, `tinyurl`, `t.co`).
* **Sensitive Security Keywords:** Detects credential-harvesting tokens (`login`, `verify`, `banking`, `secure`, `update`, `account`).

### 3. Shannon Entropy & Randomness Scoring
* Calculates information entropy across the hostname and path string to identify algorithmically generated domains (DGA) used by modern botnets.

## Model Evaluation Benchmarks (Held-out Test Dataset: 90,036 URLs)
* **Accuracy:** 99.41%
* **Precision:** 98.92%
* **Recall (Sensitivity):** 98.51%
* **F1-Score:** 0.9871
* **ROC-AUC:** 0.9981
* **Average Inference Latency:** ~12 milliseconds per request

---
*Author: Fenil Sojitra (@fenilsojitra242-code)*
