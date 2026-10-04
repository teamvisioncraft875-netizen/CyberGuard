"""EMBER 2018 Feature Extractor for CYBERGUARD.

Extracts a 2,381-dimensional numeric feature vector from Portable Executable (PE)
binaries for static malware classification using the EMBER 2018 LightGBM model.

Feature breakdown (EMBER 2018 v2 specification):
1. ByteHistogram: 256 dimensions (normalized byte frequency)
2. ByteEntropyHistogram: 256 dimensions (joint 16x16 byte-entropy distribution)
3. StringExtractor: 104 dimensions (string counts, lengths, character distribution, entropy, paths, urls, registry, MZ)
4. GeneralFileInfo: 10 dimensions (file size, virtual size, exports, imports, relocations, resources, signature, tls, symbols)
5. HeaderFileInfo: 62 dimensions (COFF header characteristics, optional header versions, subsystem, dll characteristics)
6. SectionInfo: 255 dimensions (section counts, sizes, entropies, virtual sizes, entry point section, characteristics)
7. ImportsInfo: 1,280 dimensions (256 hashed libraries + 1,024 hashed library:function pairs)
8. ExportsInfo: 128 dimensions (128 hashed exported function symbols)
9. DataDirectories: 30 dimensions (15 pairs of size and virtual address)

Total dimensions: 256 + 256 + 104 + 10 + 62 + 255 + 1280 + 128 + 30 = 2,381 features.

Safety:
- Static PE parsing only. Binaries are NEVER executed.
- Corrupted, truncated, or non-PE inputs return graceful fallback vectors.
"""

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import lief
import numpy as np
from sklearn.feature_extraction import FeatureHasher

logger = logging.getLogger(__name__)

# Feature dimensions
EMBER_FEATURE_DIM = 2381


class FeatureType:
    """Base class for EMBER feature extractors."""

    name: str = ""
    dim: int = 0

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Any:
        raise NotImplementedError

    def process_raw_features(self, raw_obj: Any) -> np.ndarray:
        raise NotImplementedError

    def feature_vector(self, bytez: bytes, lief_binary: Optional[Any]) -> np.ndarray:
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    """Normalized byte frequency histogram across the entire binary."""

    name = "histogram"
    dim = 256

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> List[int]:
        if not bytez:
            return [0] * 256
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total == 0:
            return np.zeros(256, dtype=np.float32)
        return counts / total


class ByteEntropyHistogram(FeatureType):
    """Joint 16x16 byte-value and local-entropy histogram."""

    name = "byteentropy"
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048):
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block: np.ndarray) -> Tuple[int, np.ndarray]:
        c = np.bincount(block >> 4, minlength=16)
        block_len = len(block)
        if block_len == 0:
            return 0, c
        p = c.astype(np.float32) / block_len
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2.0
        Hbin = int(H * 2)
        if Hbin >= 16:
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> List[int]:
        output = np.zeros((16, 16), dtype=np.int32)
        if not bytez:
            return output.flatten().tolist()

        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c

        return output.flatten().tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total == 0:
            return np.zeros(256, dtype=np.float32)
        return counts / total


class StringExtractor(FeatureType):
    """Extracts printable ASCII strings and summary statistics."""

    name = "strings"
    dim = 104

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._paths = re.compile(b"c:\\\\", re.IGNORECASE)
        self._urls = re.compile(b"https?://", re.IGNORECASE)
        self._registry = re.compile(b"HKEY_")
        self._mz = re.compile(b"MZ")

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Dict[str, Any]:
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = float(sum(string_lengths)) / len(string_lengths)
            as_shifted_string = [b - 32 for b in b"".join(allstrings)]
            c = np.bincount(as_shifted_string, minlength=96)
            csum = float(c.sum())
            if csum > 0:
                p = c.astype(np.float32) / csum
                wh = np.where(c)[0]
                H = float(np.sum(-p[wh] * np.log2(p[wh])))
            else:
                H = 0.0
        else:
            avlength = 0.0
            c = np.zeros((96,), dtype=np.float32)
            H = 0.0
            csum = 0.0

        return {
            "numstrings": len(allstrings),
            "avlength": avlength,
            "printabledist": c.tolist(),
            "printables": int(csum),
            "entropy": float(H),
            "paths": len(self._paths.findall(bytez)),
            "urls": len(self._urls.findall(bytez)),
            "registry": len(self._registry.findall(bytez)),
            "MZ": len(self._mz.findall(bytez)),
        }

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        hist_divisor = float(raw_obj["printables"]) if raw_obj.get("printables", 0) > 0 else 1.0
        printabledist = np.asarray(raw_obj.get("printabledist", [0.0] * 96), dtype=np.float32)
        return np.hstack([
            raw_obj.get("numstrings", 0),
            raw_obj.get("avlength", 0.0),
            raw_obj.get("printables", 0),
            printabledist / hist_divisor,
            raw_obj.get("entropy", 0.0),
            raw_obj.get("paths", 0),
            raw_obj.get("urls", 0),
            raw_obj.get("registry", 0),
            raw_obj.get("MZ", 0),
        ]).astype(np.float32)


class GeneralFileInfo(FeatureType):
    """General PE metadata such as sizes, exported/imported function counts."""

    name = "general"
    dim = 10

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Dict[str, int]:
        if lief_binary is None:
            return {
                "size": len(bytez),
                "vsize": 0,
                "has_debug": 0,
                "exports": 0,
                "imports": 0,
                "has_relocations": 0,
                "has_resources": 0,
                "has_signature": 0,
                "has_tls": 0,
                "symbols": 0,
            }

        has_sig = getattr(lief_binary, "has_signatures", getattr(lief_binary, "has_signature", False))

        return {
            "size": len(bytez),
            "vsize": int(getattr(lief_binary, "virtual_size", 0)),
            "has_debug": int(bool(getattr(lief_binary, "has_debug", False))),
            "exports": len(getattr(lief_binary, "exported_functions", [])),
            "imports": len(getattr(lief_binary, "imported_functions", [])),
            "has_relocations": int(bool(getattr(lief_binary, "has_relocations", False))),
            "has_resources": int(bool(getattr(lief_binary, "has_resources", False))),
            "has_signature": int(bool(has_sig)),
            "has_tls": int(bool(getattr(lief_binary, "has_tls", False))),
            "symbols": len(getattr(lief_binary, "symbols", [])),
        }

    def process_raw_features(self, raw_obj: Dict[str, int]) -> np.ndarray:
        return np.asarray([
            raw_obj.get("size", 0),
            raw_obj.get("vsize", 0),
            raw_obj.get("has_debug", 0),
            raw_obj.get("exports", 0),
            raw_obj.get("imports", 0),
            raw_obj.get("has_relocations", 0),
            raw_obj.get("has_resources", 0),
            raw_obj.get("has_signature", 0),
            raw_obj.get("has_tls", 0),
            raw_obj.get("symbols", 0),
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    """Machine, architecture, OS, linker and other information from PE headers."""

    name = "header"
    dim = 62

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Dict[str, Any]:
        raw_obj: Dict[str, Any] = {
            "coff": {"timestamp": 0, "machine": "", "characteristics": []},
            "optional": {
                "subsystem": "",
                "dll_characteristics": [],
                "magic": "",
                "major_image_version": 0,
                "minor_image_version": 0,
                "major_linker_version": 0,
                "minor_linker_version": 0,
                "major_operating_system_version": 0,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 0,
                "minor_subsystem_version": 0,
                "sizeof_code": 0,
                "sizeof_headers": 0,
                "sizeof_heap_commit": 0,
            },
        }

        if lief_binary is None:
            return raw_obj

        try:
            if hasattr(lief_binary, "header"):
                hdr = lief_binary.header
                raw_obj["coff"]["timestamp"] = getattr(hdr, "time_date_stamps", 0)
                raw_obj["coff"]["machine"] = str(getattr(hdr, "machine", "")).split(".")[-1]
                ch_list = getattr(hdr, "characteristics_list", getattr(hdr, "characteristics_lists", []))
                raw_obj["coff"]["characteristics"] = [str(c).split(".")[-1] for c in ch_list]

            if hasattr(lief_binary, "optional_header"):
                opt = lief_binary.optional_header
                raw_obj["optional"]["subsystem"] = str(getattr(opt, "subsystem", "")).split(".")[-1]

                # Resolve DLL characteristics
                dll_chars = getattr(opt, "dll_characteristics_lists", getattr(opt, "dll_characteristics_list", []))
                resolved_dll = []
                for c in dll_chars:
                    if hasattr(c, "name"):
                        resolved_dll.append(c.name)
                    else:
                        try:
                            enum_val = lief.PE.OptionalHeader.DLL_CHARACTERISTICS(c)
                            resolved_dll.append(str(enum_val).split(".")[-1])
                        except Exception:
                            resolved_dll.append(str(c).split(".")[-1])
                raw_obj["optional"]["dll_characteristics"] = resolved_dll

                raw_obj["optional"]["magic"] = str(getattr(opt, "magic", "")).split(".")[-1]
                raw_obj["optional"]["major_image_version"] = getattr(opt, "major_image_version", 0)
                raw_obj["optional"]["minor_image_version"] = getattr(opt, "minor_image_version", 0)
                raw_obj["optional"]["major_linker_version"] = getattr(opt, "major_linker_version", 0)
                raw_obj["optional"]["minor_linker_version"] = getattr(opt, "minor_linker_version", 0)
                raw_obj["optional"]["major_operating_system_version"] = getattr(opt, "major_operating_system_version", 0)
                raw_obj["optional"]["minor_operating_system_version"] = getattr(opt, "minor_operating_system_version", 0)
                raw_obj["optional"]["major_subsystem_version"] = getattr(opt, "major_subsystem_version", 0)
                raw_obj["optional"]["minor_subsystem_version"] = getattr(opt, "minor_subsystem_version", 0)
                raw_obj["optional"]["sizeof_code"] = getattr(opt, "sizeof_code", 0)
                raw_obj["optional"]["sizeof_headers"] = getattr(opt, "sizeof_headers", 0)
                raw_obj["optional"]["sizeof_heap_commit"] = getattr(opt, "sizeof_heap_commit", 0)
        except Exception as e:
            logger.debug(f"Header extraction fallback: {e}")

        return raw_obj

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        coff = raw_obj.get("coff", {})
        opt = raw_obj.get("optional", {})
        return np.hstack([
            coff.get("timestamp", 0),
            FeatureHasher(10, input_type="string").transform([[coff.get("machine", "")]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([coff.get("characteristics", [])]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[opt.get("subsystem", "")]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([opt.get("dll_characteristics", [])]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[opt.get("magic", "")]]).toarray()[0],
            opt.get("major_image_version", 0),
            opt.get("minor_image_version", 0),
            opt.get("major_linker_version", 0),
            opt.get("minor_linker_version", 0),
            opt.get("major_operating_system_version", 0),
            opt.get("minor_operating_system_version", 0),
            opt.get("major_subsystem_version", 0),
            opt.get("minor_subsystem_version", 0),
            opt.get("sizeof_code", 0),
            opt.get("sizeof_headers", 0),
            opt.get("sizeof_heap_commit", 0),
        ]).astype(np.float32)


class SectionInfo(FeatureType):
    """Section properties, sizes, and entropy using FeatureHasher."""

    name = "section"
    dim = 255

    @staticmethod
    def _properties(s: Any) -> List[str]:
        ch_list = getattr(s, "characteristics_lists", getattr(s, "characteristics_list", []))
        return [str(c).split(".")[-1] for c in ch_list]

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Dict[str, Any]:
        if lief_binary is None:
            return {"entry": "", "sections": []}

        entry_section = ""
        try:
            entrypoint = getattr(lief_binary, "entrypoint", 0)
            imagebase = getattr(lief_binary, "imagebase", 0)
            section = lief_binary.section_from_rva(entrypoint - imagebase)
            if section is not None:
                entry_section = section.name
        except Exception:
            pass

        if not entry_section:
            # Fallback: look for executable section
            for s in getattr(lief_binary, "sections", []):
                props = self._properties(s)
                if "MEM_EXECUTE" in props:
                    entry_section = s.name
                    break

        sections = []
        for s in getattr(lief_binary, "sections", []):
            sections.append({
                "name": str(getattr(s, "name", "")),
                "size": int(getattr(s, "size", 0)),
                "entropy": float(getattr(s, "entropy", 0.0)),
                "vsize": int(getattr(s, "virtual_size", 0)),
                "props": self._properties(s),
            })

        return {"entry": entry_section, "sections": sections}

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        sections = raw_obj.get("sections", [])
        entry = raw_obj.get("entry", "")

        general = [
            len(sections),
            sum(1 for s in sections if s.get("size", 0) == 0),
            sum(1 for s in sections if s.get("name", "") == ""),
            sum(1 for s in sections if "MEM_READ" in s.get("props", []) and "MEM_EXECUTE" in s.get("props", [])),
            sum(1 for s in sections if "MEM_WRITE" in s.get("props", [])),
        ]

        section_sizes = [(s.get("name", ""), s.get("size", 0)) for s in sections]
        section_sizes_hashed = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]

        section_entropy = [(s.get("name", ""), s.get("entropy", 0.0)) for s in sections]
        section_entropy_hashed = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]

        section_vsize = [(s.get("name", ""), s.get("vsize", 0)) for s in sections]
        section_vsize_hashed = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]

        # Note: double brackets required for scikit-learn 1.4+ compatibility
        entry_name_hashed = FeatureHasher(50, input_type="string").transform([[entry]]).toarray()[0]

        characteristics = [p for s in sections for p in s.get("props", []) if s.get("name", "") == entry]
        characteristics_hashed = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]

        return np.hstack([
            general,
            section_sizes_hashed,
            section_entropy_hashed,
            section_vsize_hashed,
            entry_name_hashed,
            characteristics_hashed,
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    """Imported libraries and functions from the Import Address Table."""

    name = "imports"
    dim = 1280

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> Dict[str, List[str]]:
        imports: Dict[str, List[str]] = {}
        if lief_binary is None:
            return imports

        for lib in getattr(lief_binary, "imports", []):
            lib_name = getattr(lib, "name", "")
            if not lib_name:
                continue
            if lib_name not in imports:
                imports[lib_name] = []

            for entry in getattr(lib, "entries", []):
                if getattr(entry, "is_ordinal", False):
                    imports[lib_name].append(f"ordinal{getattr(entry, 'ordinal', 0)}")
                else:
                    entry_name = getattr(entry, "name", "")
                    if entry_name:
                        imports[lib_name].append(entry_name[:10000])

        return imports

    def process_raw_features(self, raw_obj: Dict[str, List[str]]) -> np.ndarray:
        libraries = list(set([l.lower() for l in raw_obj.keys()]))
        libraries_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]

        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]

        return np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)


class ExportsInfo(FeatureType):
    """Exported function names."""

    name = "exports"
    dim = 128

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> List[str]:
        if lief_binary is None:
            return []

        clipped_exports = []
        for export in getattr(lief_binary, "exported_functions", []):
            if hasattr(export, "name"):
                clipped_exports.append(str(export.name)[:10000])
            else:
                clipped_exports.append(str(export)[:10000])
        return clipped_exports

    def process_raw_features(self, raw_obj: List[str]) -> np.ndarray:
        exports_hashed = FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0]
        return exports_hashed.astype(np.float32)


class DataDirectories(FeatureType):
    """Sizes and virtual addresses of the first 15 PE data directories."""

    name = "datadirectories"
    dim = 30

    _name_order = [
        "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
        "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE",
        "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
    ]

    def raw_features(self, bytez: bytes, lief_binary: Optional[Any]) -> List[Dict[str, Any]]:
        output = []
        if lief_binary is None:
            return output

        for data_directory in getattr(lief_binary, "data_directories", []):
            output.append({
                "name": str(getattr(data_directory, "type", "")).replace("DATA_DIRECTORY.", ""),
                "size": int(getattr(data_directory, "size", 0)),
                "virtual_address": int(getattr(data_directory, "rva", 0)),
            })
        return output

    def process_raw_features(self, raw_obj: List[Dict[str, Any]]) -> np.ndarray:
        features = np.zeros(2 * len(self._name_order), dtype=np.float32)
        for i in range(len(self._name_order)):
            if i < len(raw_obj):
                features[2 * i] = float(raw_obj[i].get("size", 0))
                features[2 * i + 1] = float(raw_obj[i].get("virtual_address", 0))
        return features


class PEFeatureExtractor:
    """Production-grade EMBER 2018 v2 feature extractor."""

    def __init__(self):
        self.features: List[FeatureType] = [
            ByteHistogram(),
            ByteEntropyHistogram(),
            StringExtractor(),
            GeneralFileInfo(),
            HeaderFileInfo(),
            SectionInfo(),
            ImportsInfo(),
            ExportsInfo(),
            DataDirectories(),
        ]
        self.dim: int = sum(fe.dim for fe in self.features)
        assert self.dim == EMBER_FEATURE_DIM, f"Expected {EMBER_FEATURE_DIM} dims, got {self.dim}"

    def raw_features(self, bytez: bytes) -> Dict[str, Any]:
        """Extract raw feature dictionary from byte buffer."""
        lief_binary = None
        # Only attempt LIEF parse if buffer looks like a PE executable (starts with MZ)
        if len(bytez) >= 64 and bytez[:2] == b"MZ":
            try:
                lief_binary = lief.PE.parse(list(bytez))
            except Exception as e:
                logger.debug(f"LIEF parse failed: {e}")
                lief_binary = None

        features: Dict[str, Any] = {
            "sha256": hashlib.sha256(bytez).hexdigest(),
            "md5": hashlib.md5(bytez).hexdigest(),
        }
        for fe in self.features:
            features[fe.name] = fe.raw_features(bytez, lief_binary)
        return features

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        """Transform raw feature dictionary into a 2,381-dimensional vector."""
        vectors = []
        for fe in self.features:
            val = raw_obj.get(fe.name)
            if val is None:
                # Fallback to empty representation
                val = fe.raw_features(b"", None)
            vectors.append(fe.process_raw_features(val))
        return np.hstack(vectors).astype(np.float32)

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """Direct extraction: bytes -> 2,381-dimensional float32 vector."""
        return self.process_raw_features(self.raw_features(bytez))
