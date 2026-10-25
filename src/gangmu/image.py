"""Is this function in the firmware image?

``--gc-sections`` with ``-ffunction-sections`` throws away every function nothing kept
refers to, so a source tree that contains a vulnerable function can still ship an image
that does not. Two artefacts of the build say so, per function:

* the GNU ld link map lists every ``.text.NAME`` section, as kept (in the memory map) or
  discarded, with the object it came from;
* the linked ELF's symbol table lists the functions that are in the image, when it has not
  been stripped.

``linked``              a kept section or a function symbol of that name is in the image
``discarded``           the linker dropped the function's section and nothing else of that
                        name was kept: the out-of-line copy is not in the image
``absent-from-symbols`` the image has a symbol table and no function of that name (weaker:
                        the compiler may have inlined it, so this is a hint, not a verdict)
``unknown``             neither artefact says anything about the name

What this cannot see: a copy of the function inlined into a caller that was kept, code
placed by a linker script ``KEEP()`` the map does not show by function, and any build
without function sections (the map is then silent, which is reported as ``unknown``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Collection, List, Optional, Set, Tuple

from .build.facts import _object_stem
from .build.linkmap import FunctionSections, parse_function_sections
from .elf import parse_elf


@dataclass
class ImageFunctions:
    sections: FunctionSections = field(default_factory=FunctionSections)
    symbols: Optional[Set[str]] = None       # None: no readable symbol table
    notes: List[str] = field(default_factory=list)

    def informative(self) -> bool:
        return bool(self.sections) or bool(self.symbols)

    def state(self, name: str, stems: Collection[str] = ()) -> Tuple[str, str]:
        """(state, evidence) for one function; ``stems`` are the object stems of the source
        files that define it, to tell two static functions of one name apart."""
        kept = self._of(self.sections.kept.get(name), stems)
        dropped = self._of(self.sections.discarded.get(name), stems)
        if self.sections.kept.get(name) and not kept and not dropped:
            kept = set(self.sections.kept[name])      # no stem matched: every copy counts
        if self.sections.discarded.get(name) and not kept and not dropped:
            dropped = set(self.sections.discarded[name])
        if self.symbols is not None and name in self.symbols:
            return "linked", f"{name} is a function symbol of the linked image"
        if kept:
            return "linked", f"the link map keeps .text.{name} from {sorted(kept)[0]}"
        if dropped:
            return "discarded", (f"the linker discarded .text.{name} from "
                                 f"{sorted(dropped)[0]} and kept no other copy")
        if self.symbols:
            return "absent-from-symbols", (f"no function symbol {name} in the linked image "
                                           "(it may have been inlined)")
        return "unknown", ""

    @staticmethod
    def _of(objects: Optional[Set[str]], stems: Collection[str]) -> Set[str]:
        if not objects or not stems:
            return set()
        wanted = {s.lower() for s in stems}
        return {o for o in objects if _object_stem(o) in wanted}


def load_image(link_map: Optional[Path] = None, elf: Optional[Path] = None) -> ImageFunctions:
    image = ImageFunctions()
    if link_map is not None:
        image.sections = parse_function_sections(Path(link_map))
        if not image.sections:
            image.notes.append(f"{link_map} has no per-function sections (.text.NAME): the "
                               "build did not use -ffunction-sections, or the map is not GNU ld's")
    if elf is not None:
        info = parse_elf(Path(elf).read_bytes())
        if info is None:
            image.notes.append(f"{elf} is not an ELF file")
        elif info.stripped:
            image.notes.append(f"{elf} is stripped: it has no function symbols to read")
        else:
            image.symbols = {name for _addr, _size, name in info.functions}
    return image
