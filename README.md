# Password Security Research: Cracking Feasibility & Defensive Analysis

## Overview
This project presents an ethical, controlled study of password security, evaluating how different hashing algorithms, password policies, and defensive controls impact real-world attack feasibility.

The goal is to translate offensive results into **actionable defensive recommendations** for enterprise environments.

## Threat Model
- Attacker has access to a leaked password hash database
- Attacks are performed **offline only**
- No rate limits or account lockouts apply during cracking

## Research Questions
- How does hash algorithm choice affect crack time and cost?
- What is the impact of salting and peppering?
- Do long passphrases outperform complex passwords?
- How effective are modern defenses such as MFA?

## Methodology
1. Prepare an ethically sourced password dataset
2. Hash passwords using multiple algorithms
3. Perform controlled cracking experiments
4. Analyze success rates and time-to-compromise
5. Translate results into defensive guidance

## Key Results (Summary)
- Memory-hard algorithms significantly increase attack cost
- Password length outperforms complexity
- Unsalted hashes are catastrophically weak

## Defensive Recommendations
- Use Argon2 or bcrypt with unique salts
- Enforce long passphrases over complexity rules
- Require MFA for all external authentication

## Ethics Statement
This research follows responsible disclosure and ethical security research principles. No real user accounts or live systems were targeted.

## Reproducibility
All experiments can be reproduced using the provided scripts and configuration files.
