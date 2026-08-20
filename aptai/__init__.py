"""aptai -- LLM-assisted unattended APT upgrades for Debian/Ubuntu.

Design constraints (see README):

* Standard library only.  This tool must keep working when the package
  manager itself is broken, so it must not depend on anything that is
  installed through ``apt`` or ``pip``.  That is also why the Claude API is
  spoken over raw HTTPS with :mod:`urllib.request` instead of the official
  ``anthropic`` SDK.
* Nothing that the language model returns is ever passed to a shell.  The
  model may only choose from a closed vocabulary of typed actions that this
  package implements itself (see :mod:`aptai.plan` and :mod:`aptai.policy`).
"""

from aptai.version import __version__

__all__ = ["__version__"]
