# certstream-extender

An extension to the [certstream-python](https://github.com/CaliDog/certstream-python/) project. The purpose of this wrapper is to both output the certificates to disk for later review as well as provide the capability for monitoring new certificates through the use of regular expressions.

# Installation
The project is Python3 native and the only dependency is the certstream-python library. This can be installed with `pip3 install certstream`

# Future State
This script is a quick implementation but ideas for extending it include:
* Outputting more certificate details to disk
* ~~Deduplicating certificate information stored on disk~~
* Rolling output file based on time (e.g. one day)
* ~~Outputting certificates into a database (e.g. SQLite)~~
* Perform benchmarking to understand if anything is being lost when writing to disk
* Linting, PEP8 compliance, etc.
