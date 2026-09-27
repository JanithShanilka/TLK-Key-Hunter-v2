"""Read captured PT_LOAD bytes from Linux x86-64 ELF core files."""
import mmap
import struct
from bisect import bisect_right


class CoreMemory:
    def __init__(self, path):
        self.handle = open(path, "rb")
        self.data = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            if len(self.data) < 64 or self.data[:6] != b"\x7fELF\x02\x01":
                raise ValueError("Requires a little-endian ELF64 core")
            header = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data)
            if header[1:3] != (4, 62):
                raise ValueError("Requires an x86-64 ET_CORE file")
            phoff, phentsize, phnum = header[5], header[9], header[10]
            if phnum == 0xFFFF or phentsize < 56:
                raise ValueError("Unsupported program-header layout")
            if phoff + phnum * phentsize > len(self.data):
                raise ValueError("Truncated program headers")
            self.segments = []
            for index in range(phnum):
                kind, flags, offset, address, _, size, memsize, _ = struct.unpack_from("<IIQQQQQQ", self.data, phoff + index * phentsize)
                if kind != 1 or not size:
                    continue
                if size > memsize or offset + size > len(self.data):
                    raise ValueError("Truncated or invalid PT_LOAD segment")
                self.segments.append((address, size, offset, flags))
            self.segments.sort()
            self.bases = [segment[0] for segment in self.segments]
            for left, right in zip(self.segments, self.segments[1:]):
                if left[0] + left[1] > right[0]:
                    raise ValueError("Overlapping captured address ranges")
        except Exception:
            self.close()
            raise

    def close(self):
        self.data.close()
        self.handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read(self, address, length):
        if length < 0:
            raise ValueError("Negative read length")
        result = bytearray()
        while length:
            index = bisect_right(self.bases, address) - 1
            if index < 0:
                raise ValueError("Address range was not completely captured")
            base, size, offset, _ = self.segments[index]
            if address >= base + size:
                raise ValueError("Address range was not completely captured")
            count = min(length, base + size - address)
            result.extend(self.data[offset + address - base:offset + address - base + count])
            address += count
            length -= count
        return bytes(result)

    def find(self, pattern):
        # Searches within captured segments; ELF notes and omitted pages are excluded.
        if not pattern:
            raise ValueError("Empty search pattern")
        tail = b""
        previous_end = None
        for address, size, offset, _ in self.segments:
            if previous_end == address and tail:
                prefix = self.data[offset:offset + min(size, len(pattern) - 1)]
                joined = tail + prefix
                boundary = joined.find(pattern)
                while boundary != -1:
                    if boundary < len(tail) and boundary + len(pattern) > len(tail):
                        yield address - len(tail) + boundary
                    boundary = joined.find(pattern, boundary + 1)
            position = self.data.find(pattern, offset, offset + size)
            while position != -1:
                yield address + position - offset
                position = self.data.find(pattern, position + 1, offset + size)
            if len(pattern) > 1:
                current_tail = self.data[offset + max(0, size - len(pattern) + 1):offset + size]
                tail = ((tail if previous_end == address else b"") + current_tail)[-(len(pattern) - 1):]
            previous_end = address + size
