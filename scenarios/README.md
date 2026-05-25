# Scenarios

Attack scenario library. Each YAML file describes an ordered sequence of
Atomic Red Team tests targeting specific ATT&CK techniques.

## Schema

```yaml
name: Credential Access via LSASS
description: Simulate credential dumping via LSASS process access
mitre:
  - T1003.001  # OS Credential Dumping: LSASS Memory
severity: high
steps:
  - technique: T1003.001
    art_test: 1         # Atomic test number within the technique
    timeout: 120
    expected_alert: true
cleanup: true
```

## Usage

```bash
./dv scenarios list
./dv scenarios run scenarios/credential-access.yml
```
