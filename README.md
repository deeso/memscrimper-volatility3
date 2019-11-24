
volatility 3 command: `vol -f test-config.json windows.pslist`

# Installation

0) Install the `memscrimper-parser`
1) First clone volatility3: https://github.com/volatilityfoundation/volatility3
2) Second clone this repo and copy files to the following locations:
   * `memscrimper_layer.py` -->  `volatility3/volatility/framework/layers/`
   * `ms_multi_pslist.py` --> `volatility3/volatility/framework/plugins/`
   * `ms_pslist.py` --> `volatility3/volatility/framework/plugins/`
3) Change directories too `volatility3/`
4) `python3 setup.py install`

# Configuration

Create a file `memscrimper-config.json`, and create JSON stanzas similar to the ones below.
* `filetype`: required, defines the config file
* `MemscrimperLayer.location`: required, location to the diff file
* `MemscrimperLayer.reference`: required, location to the memory the diff is based on
* `MemscrimperLayer.preload`: optional, preload the raw reference file into memory
* `MemscrimperLayer.analyze`: required, select initial analysis on raw file or diff (`source` or `reference`)
* `MemscrimperLayer.diffs`: optional, diffs to load into the environment (on demand) for analysis


### Configuring a single file to analyze
```json
{
  "filetype": "Memscrimper",
  "MemscrimperLayer.location": "/data/memory_dumps/baseline-test-4.compress",
  "MemscrimperLayer.reference": "/data/memory_dumps/baseline-test-1.raw",
  "MemscrimperLayer.preload": true
}

```
### Configuring an environment to handle more than one diff
```json
{
  "filetype": "Memscrimper",
  "MemscrimperLayer.location": "/data/plugx/010.dump.diff",
  "MemscrimperLayer.reference": "/data/plugx/001.dump.raw",
  "MemscrimperLayer.preload": true,
  "MemscrimperLayer.analyze": "source",
  "MemscrimperLayer.diffs": ["/data/plugx/015.dump.diff",
                              "/data/plugx/024.dump.diff",
                              "/data/plugx/027.dump.diff"]
}

```

# Usages 

* `vol -f test-config.json windows.pslist`
    * Uses volatility plugins naturally. performs pslist against the raw memory file or diff, 
    depending on the selected `MemscrimperLayer.analyze` parameter
* `vol -f test-config.json ms_multi_ps_list`
    * New volatility plugin. Performs pslist against reference and diff files and then prints the
    new, present, and dead processes annotating the __first__ and __last__ observation. 
* `vol -f test-config.json ms_ps_list`
    * New volatility plugin. Performs pslist against the raw memory file and diff. 
    
    
# Notes

Address spaces are loaded as layers.  Generally, volatility was intended to analyze
one file, so there is no real support for loading (multiple) files for analysis via the CLI.
The easiest way for me to load the diff and reference files was to create a configuration
file and then load files in the layers when the layers were being loaded based on the configuration.

The `MemscrimperLayer` takes the information in the configuration file, and
loads the diff and reference files.  This layer overloads the read functions
as a `FileLayer`.  This means all reads and writes must drive through the file.
This also provides control, where we can select (toggle) which files are read.
This may not be best practices, but without any clear documentation or direction
in the source code, this approach could be accomplished with the least friction.

Another consideration is _caching_.  volatility uses Python3 functionality to 
cache common function calls using memoization.  Since the files used to read
information about our processes (e.g.  multiple diff files and even the raw sample),
caching can create misleading analysis.  Hence, special care must be taken to clear
the function cache to remove the memoization.

The Memscrimper parser does most of all the other heavy lifting.  
