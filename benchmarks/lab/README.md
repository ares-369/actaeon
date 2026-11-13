# Lab benchmark on your own data

Scores Actaeon on a frozen copy of real data from your environment, with cases whose answer you know.
A public benchmark tells you whether it can investigate; this tells you whether it works on your network.

## 1. Plant, then freeze

1. On a throwaway host with your endpoint agent, plant a few harmless, attack-shaped artifacts that
   your detections may not cover: a process started from `/dev/shm`, a listener on an odd port from a
   hidden copy of an interpreter in `/var/tmp`, a second UID 0 account with a locked password, log
   lines that contain real indicators from an advisory in your intel store. Confirm each one reached
   the SIEM (alerts, raw events or inventory) before going on: a hunter cannot find what is not collected.
2. Freeze the data: `python3 snapshot.py <anchor time>` copies alerts, raw events, inventory and
   vulnerability findings into `actaeon-bench-*` indices with their mappings.
3. Remove the throwaway host. The planted activity lives on in the frozen copy.

## 2. Point a separate Actaeon home at the frozen data

Copy your normal `config.yaml` (environment profile, known-good list, models) to a new home and change
the connectors to the `actaeon-bench-*` indices. Set `BRIDGE_NOW: "<anchor time>"` in each connector's
`env`, so "the last 7 days" always means the same frozen week. Copy your `data/intel.sqlite` if you
want real intel in the cases.

## 3. Write cases and run

See `cases.example.yaml`. Label only what you know: what you planted, and real activity you checked
by hand. Then:

```bash
ACTAEON_HOME=<bench home> actaeon bench --cases cases.yaml --workers 4
```

The report lists each case, accuracy, threat precision and recall, tokens and time. Hunts Actaeon could
not answer open "needs analyst" leads, which you can review in the bench home's UI.

## Honest limits

Your own cases are small and written by someone who knows the answers, so the hypotheses point at the
right area. Treat a perfect score as "it checks and clears correctly", not as proof it finds stealthy
attackers. Run each case more than once: confidence varies between runs.
