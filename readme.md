# modality <img src="docs/logo.png" align="right" alt="logo" width="240">

A **radare2** plugin to integrate the symbolic execution capabilities of **angr**. 

---

This project is *mid-development so bugs and missing features are expected*. The tool has partial gitbook [documentation](https://chasekanipe.gitbook.io/modality/). 

<br>

<p align="center">
  <img src="docs/preview.gif" />
</p>

---

## Installation (Manual)
First install the python prerequisites

```
pip3 install angr termcolor r2pipe angrdbg cooldict
```

Then install r2lang

```
r2pm -i lang-python
```

Then clone the modality repo into the r2pm git folder.

```
git clone https://github.com/0xchase/modality .local/share/radare2/r2pm/git/modality
```

Copy the top level script to the plugins folder.

```
cp .local/share/radare2/r2pm/git/modality/plugin.py .local/share/radare2/plugins/modality.py
```

Then add the following lines to your `.bashrc`

```
export PYTHONPATH=~/.local/share/radare2/r2pm/git/modality/:~/.local/share/radare2/r2pm/git/modality/src:
```

The tool has only been tested on Ubuntu 20.04 (so far). If you have installation issues feel free to create a git issue.

---

## Goals

This project intends to
 - Better integrate symbolic execution with the rest of the reverse engineering process
 - Provide a faster alternative to using angr than writing scripts
 - Provide useful visualizations of the angr backend
 - Allow for switching between concrete and symbolic execution (this feature is coming soon)
 - Include a suite of features for vulnerability detection, exploit generation, etc (coming soon)


---

*Contact me at chasekanipe [at] gmail [dot] com*
