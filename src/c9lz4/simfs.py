"""A tiny in-memory model of one temporary directory on Linux.

Nothing here touches the real filesystem: entries live in a dict. Only the
rules the GHSA names are modelled: exclusive creation, O_CREAT|O_TRUNC opens
that follow symlinks, the sticky bit, and the fs.protected_regular /
fs.protected_symlinks sysctls (which, in Linux, apply only inside
world-writable sticky directories).
"""
from __future__ import annotations

from dataclasses import dataclass, field

DIR_OWNER = "root"
OUTSIDE = "outside:"  # prefix for symlink targets outside the directory


class FsError(Exception):
    """EEXIST / EACCES / ENOENT in the model."""

    def __init__(self, errno: str, why: str):
        super().__init__(f"{errno}: {why}")
        self.errno = errno
        self.why = why


@dataclass
class Entry:
    kind: str  # "file" or "symlink"
    owner: str
    world_writable: bool = False
    content: str = ""
    target: str = ""  # symlinks only
    mtime: int = 0


@dataclass
class TmpDir:
    world_writable: bool = True
    sticky: bool = True
    protected_regular: int = 0
    protected_symlinks: int = 0
    entries: dict = field(default_factory=dict)
    outside: dict = field(default_factory=dict)  # symlink targets
    log: list = field(default_factory=list)

    # -- helpers -----------------------------------------------------------
    def _shared_sticky(self) -> bool:
        return self.world_writable and self.sticky

    def can_write_dir(self, user: str) -> bool:
        return user == DIR_OWNER or user == "victim" or self.world_writable

    # -- operations --------------------------------------------------------
    def create_exclusive(self, name: str, user: str, mtime: int = 0,
                         world_writable: bool = False, content: str = "") -> None:
        """open(O_CREAT|O_EXCL): fails if anything, even a symlink, exists."""
        if not self.can_write_dir(user):
            raise FsError("EACCES", f"{user} cannot create in the directory")
        if name in self.entries:
            raise FsError("EEXIST", name)
        self.entries[name] = Entry("file", user, world_writable, content,
                                   mtime=mtime)
        self.log.append(f"{user} create_exclusive {name}")

    def symlink(self, name: str, user: str, target: str) -> None:
        if not self.can_write_dir(user):
            raise FsError("EACCES", f"{user} cannot create in the directory")
        if name in self.entries:
            raise FsError("EEXIST", name)
        self.entries[name] = Entry("symlink", user, target=target)
        self.log.append(f"{user} symlink {name} -> {target}")

    def unlink(self, name: str, user: str) -> None:
        e = self.entries.get(name)
        if e is None:
            raise FsError("ENOENT", name)
        if not self.can_write_dir(user):
            raise FsError("EACCES", f"{user} cannot unlink in the directory")
        if self.sticky and user not in (e.owner, DIR_OWNER):
            raise FsError("EACCES", "sticky directory: not the owner")
        del self.entries[name]
        self.log.append(f"{user} unlink {name}")

    def open_write(self, name: str, user: str, mtime: int = 0) -> Entry:
        """open(O_WRONLY|O_CREAT|O_TRUNC), what FileOutputStream does."""
        e = self.entries.get(name)
        if e is None:
            self.create_exclusive(name, user, mtime=mtime)
            return self.entries[name]
        if e.kind == "symlink":
            if (self._shared_sticky() and self.protected_symlinks >= 1
                    and user != e.owner and e.owner != DIR_OWNER):
                raise FsError("EACCES", "fs.protected_symlinks")
            tgt = self.outside.get(e.target)
            if tgt is None:
                tgt = Entry("file", user)
                self.outside[e.target] = tgt
            elif tgt.owner != user and not tgt.world_writable:
                raise FsError("EACCES", "symlink target not writable")
            tgt.content = ""
            self.log.append(f"{user} open_write {name} (follows -> {e.target})")
            return tgt
        if (self._shared_sticky() and self.protected_regular >= 1
                and user not in (e.owner, DIR_OWNER)):
            raise FsError("EACCES", "fs.protected_regular")
        if e.owner != user and not e.world_writable:
            raise FsError("EACCES", "file not writable")
        e.content = ""
        self.log.append(f"{user} open_write {name} (existing, owner {e.owner})")
        return e

    def resolve(self, name: str) -> Entry | None:
        e = self.entries.get(name)
        if e is not None and e.kind == "symlink":
            return self.outside.get(e.target)
        return e
