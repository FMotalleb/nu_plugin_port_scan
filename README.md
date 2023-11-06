# nu_plugin_port_scan

A [nushell](https://www.nushell.sh/) plugin for scanning ports on a target

Similar to `nc -vz {ip} {port} -w {timeout}` the parameters are mapped to `port scan {ip} {port} -t {timeout}`

## Examples

```bash
~> port scan 8.8.8.8 53
╭──────────────┬─────────╮
│ address      │ 8.8.8.8 │
│ port         │ 53      │
│ result       │ Open    │
│ elapsed (ms) │ 37      │
╰──────────────┴─────────╯
```

```bash
~> 15..25 | each { |it| port scan 127.0.0.1 $it -t 1ms } |  where result == Open
╭───┬───────────┬──────┬────────┬──────────────╮
│ # │ address   │ port │ result │ elapsed (ms) │
├───┼───────────┼──────┼────────┼──────────────┤
│ 0 │ 127.0.0.1 │ 21   │ Open   │ 0            │
│ 1 │ 127.0.0.1 │ 22   │ Open   │ 0            │
╰───┴───────────┴──────┴────────┴──────────────╯
```

## Installing

* via git

```bash
git clone https://github.com/FMotalleb/nu_plugin_port_scan.git
cd nu_plugin_port_scan
cargo build
register target/debug/nu_plugin_port_scan
```
