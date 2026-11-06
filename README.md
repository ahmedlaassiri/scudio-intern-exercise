# Scudio practical exercise – C++ Debugging & QA Intern

Answer to the practical exercise. Four customer reports were investigated from the Application Insights log exports and a WinDbg crash dump; they come down to three distinct defects.

| File | Content |
| --- | --- |
| [`tickets.md`](tickets.md) | Four tickets (three defects + one hardening item), report → ticket mapping, what was checked and ruled out against the known issues |
| [`kql.md`](kql.md) | KQL queries on the `traces` table to list every affected device per problem, with count and first/last occurrence |
| [`detect.py`](detect.py) | Detection script (Python 3, standard library only). Reads every CSV in a folder and prints the problems found per device |
| [`detection_output.txt`](detection_output.txt) | Output of the script on the four provided logs |
| [`NOTES.md`](NOTES.md) | Continuous detection on Azure, where an LLM fits and its risks, and how AI assistance was used and verified |

The exercise materials themselves (support reports, logs, crash dump, known issues) are not included here: they belong to Scudio.

## Running the script

```
python3 detect.py <folder-with-csv-exports>        # human-readable
python3 detect.py <folder-with-csv-exports> --json # machine-readable
```
