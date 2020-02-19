![Build Mono](https://github.com/mammo0/networkminer-cli/workflows/Build%20Mono/badge.svg)

# networkminer-cli

Minimal version of https://www.netresec.com/?page=NetworkMiner

In this version the GUI is removed and replaced by a CLI interface.

The purpose of this fork is to extract only the files from a network data stream. Nothing more ore less...


### Usage

```
NetworkMiner.exe [--debug|--eventlog|--filelog] <PCAP_FILE>
```

On **Linux** use **Mono** to start: `mono NetworkMiner.exe ...`

The only mandatory parameter is a single PCAP file which <u>must</u> be the last one! The other arguments are:

- `--debug`<br/>
Activates debug logging on console.
- `--eventlog`<br/>
Activates debug logging in the event log.
- `--filelog`</br>
Activates debug logging to a log file.

Some other options, e.g. starting with multiple PCAP files or a directory will may be added in a future release.


### Results

After the program has finished the extracted files can be found in the newly created directory `AssembledFiles`.
