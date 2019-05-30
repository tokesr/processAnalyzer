#processAnalyzer

.processAnalyzer is a Python tool to analyze the csv output of the following osquery command:

select p.pid, p.name, p.path, p.parent, p.cmdline, p.start_time, p.elapsed_time, p.on_disk, h.md5, h.sha256 from processes p left outer join hash h on p.path=h.path;

You can read more about the tool on [forensixchange.com](https://www.forensixchange.com)

## help menu
You can open it with the -h (--help) switch.

usage: processAnalyzer_v0_8.py [-h] [-d DELIMITER] [-s SYSTEMROOT] [-a] [-v]
                               [-k APIKEY] [-c CACHEFILE] [-p PROCESSFILE]
                               [-o OUTPUTFILE] -i INPUT -m
                               {json,analyze,learning}

optional arguments:
  -h, --help            show this help message and exit
  -d DELIMITER, --delimiter DELIMITER
                        delimiter for the csv file
  -s SYSTEMROOT, --systemroot SYSTEMROOT
                        root directory of the original system,
                        default=C:\windows\
  -a, --adapting        comparing filenames to similar known files to detect
                        masquerading attempt
  -v, --verbose         verbose
  -k APIKEY, --apikey APIKEY
                        apikey for virustotal lookup, without it virustotal
                        won't be utilized
  -c CACHEFILE, --cachefile CACHEFILE
                        you can load known hashes from a file, these ones
                        aren't going to be checked on VT
  -p PROCESSFILE, --processfile PROCESSFILE
                        file for a list of known Windows processes, default:
                        known_processes.json
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        output file for the json output, or for the result of
                        the analysis

required arguments:
  -i INPUT, --input INPUT
                        path to the csv file
  -m {json,analyze,learning}, --mode {json,analyze,learning}
                        choose json to print a json process tree, or analyze
                        to analyze the processes