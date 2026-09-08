# Data dictionary

All fraction-valued metrics use `success/eligible` notation. Denominators are part of the result and must not be discarded. Scenario 1 has 12 attack and 12 benign cells per treatment. Scenario 2 has 24 attack and 24 benign cells overall, with 8 cells per authority and condition.

| Field | Meaning |
|---|---|
| scenario | Scenario family (`scenario1` or `scenario2`). |
| experiment | Frozen experiment identifier. |
| model_treatment | Qwen 002R, Sonnet 003, or combined. |
| authority | A1, A2, A3, or combined. |
| condition | Attack, benign, or combined. |
| evidence_profile | COMPLETE or AMBIGUOUS evidence profile. |
| seed | Frozen seed set; aggregate files may report `101/202`. |
| attack_detection | Attack cells correctly detected. |
| correct_containment | Attack cells with correct containment. |
| attack_safe_success | Attack cells satisfying the safe-success endpoint. |
| benign_specificity | Benign cells correctly treated as benign. |
| false_belief | Benign cells incorrectly assessed as compromised. |
| false_containment | Benign cells receiving an inappropriate containment action. |
| proportionality | Proportionality score over its stated eligible denominator. |
| finalised | Cells reaching valid finalisation. |
| grounded_finalised | Finalised cells satisfying grounding requirements. |
| repair_required | Cells requiring at least one protocol repair. |

False belief is not false containment. Detection is not containment. A recommendation is not execution. A permitted action is not necessarily an executed action. Protocol failure is not cybersecurity reasoning failure.
