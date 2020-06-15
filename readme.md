# Modality

This project is still in development so bugs and missing features are expected. If you find one, feel free to create issues or submit pull requests.

---

## About

A radare2 plugin to quickly perform symbolic execution inside radare2 with angr, a platform-agnostic binary analysis framework by the Computer Security Lab at UC Santa Barbara and SEFCOM at Arizona State University. This plugin is intended to integrate angr in a way that's (relativley) consistent with the r2cli conventions

## Goals

This project intends to
 - Better integrate symbolic execution with the rest of the reverse engineering process
 - Provide a faster alternative to using angr than the python bindings
 - Allow for switching between concrete and symbolic execution (this feature is coming soon)
 - Provide useful visualizations of the angr backend
 - Include a suite of features for vulnerability detection, exploit generation, etc (coming soon)

