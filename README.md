# NSI Core Toolset

Collection of utilities for use across NSI projects.

## Installation

```
pip3 install nsi
```

## How to Use

The `nsi` library provides a number of utilities:

- `nsi.toolz`: Collection of general-purpose functions and types,
  patterned after the
  [`toolz`](https://toolz.readthedocs.io/en/latest/api.html)
  functional programming library and can be used as a replacement for
  toolz (i.e. it imports everything from `toolz.curried` or
  `cytoolz.curred` if `cytoolz` is installed)
- `nsi.yaml`: A few simple wrapper functions around `ruamel.yaml`
  that provides a standard interface for reading/writing YAML files
- `nsi.markdown`: Collection of
  [Python Markdown](https://python-markdown.github.io/extensions/)
  extensions
    - `MetaYamlExtension` (`meta_yaml`): A slight tweak to the
      [Meta-Data extension](https://python-markdown.github.io/extensions/meta_data/)
      for providing YAML metadata at the beginning of a markdown
      file
    - `SimpleTableExtension` (`simpletable`): A `<table>`-parsing
      extension for markdown that allows you to provide CSS classes
      for table elements within the markdown
    - `YamlDataExtension` (`yaml_data`): A more general YAML-parsing
      extension that allows you to provide chunks of YAML data
      throughout the markdown file (not just at the beginning)
- `nsi.rest`: A ReST client-building tool that attempts to be more
  functional
- `nsi.logging`: Some logging utility functions that relies on
  [`coloredlogs`](https://coloredlogs.readthedocs.io/en/latest/api.html)
  for log coloring
- `nsi.parallel`: Some functional parallelization utility functions
  designed for use within the `toolz`-ish functional idiom
- `nsi.signature`: Functions to construct a host signature, for use
  when "fingerprinting" clients is necessary
- `nsi.shell`: Shell command functions

The library also provides the following command-line tools:

- `diffips`: Given two files with IPs (A and B), get difference A - B
- `intips`: Given two files with IPs (A and B), get intersection A & B
- `difflines`: Given two files with lines of text (A and B), get
  difference A - B
- `intlines`: Given two files with lines of text (A and B), get
  intersection A & B
- `sortips`: Given text content (from clipboard, file, or stdin),
  extract IPs sort them
- `getips`: Given text content (from clipboard, file, or stdin),
  extract IPs and print them
