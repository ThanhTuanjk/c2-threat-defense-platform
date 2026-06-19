# Rules

`local_ips.rules` and `local_ids.rules` are the source rule files.

Generated files such as `active_ips.rules` and `active_ids.rules` are intentionally not committed. Build them on the gateway:

```bash
sudo /usr/local/bin/rebuild_snort_rule_sets.sh
```

Auto-generated files are represented by `.example` files in this repository. Runtime files live on the gateway:

- `/usr/local/etc/rules/local_auto.rules`
- `/usr/local/etc/rules/local_auto_ids.rules`
- `/var/lib/c2_auto_response/sid_db_v2.json`

