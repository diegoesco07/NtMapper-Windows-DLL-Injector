#ifndef PE_INSPECTOR_HPP
#define PE_INSPECTOR_HPP

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace PeInspector {

struct Section {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_offset = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
};

struct Report {
    uint16_t machine = 0;
    uint32_t image_size = 0;
    uint32_t entry_point = 0;
    uint64_t preferred_base = 0;
    std::vector<Section> sections;
    std::vector<std::string> imports;
    uint32_t relocation_blocks = 0;
    uint32_t relocation_entries = 0;
};

inline bool in_bounds(size_t offset, size_t length, size_t total) {
    return offset <= total && length <= total - offset;
}

template <typename T>
inline bool read(const std::vector<uint8_t>& bytes, size_t offset, T& value) {
    if (!in_bounds(offset, sizeof(T), bytes.size())) return false;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return true;
}

inline bool read_string(const std::vector<uint8_t>& bytes, size_t offset,
                        std::string& value, size_t maximum = 260) {
    if (offset >= bytes.size()) return false;
    size_t end = offset;
    while (end < bytes.size() && end - offset < maximum && bytes[end] != 0) ++end;
    if (end == bytes.size() || end - offset == maximum) return false;
    value.assign(reinterpret_cast<const char*>(bytes.data() + offset), end - offset);
    return true;
}

inline bool inspect(const std::vector<uint8_t>& bytes, Report& report, std::string& error) {
    report = {};
    error.clear();
    IMAGE_DOS_HEADER dos{};
    if (!read(bytes, 0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        error = "Invalid or truncated DOS header";
        return false;
    }

    const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER file{};
    if (!read(bytes, nt_offset, signature) || signature != IMAGE_NT_SIGNATURE ||
        !read(bytes, nt_offset + sizeof(DWORD), file)) {
        error = "Invalid or truncated NT header";
        return false;
    }
    if (file.Machine != IMAGE_FILE_MACHINE_AMD64) {
        error = "Only x64 (AMD64) images are supported";
        return false;
    }
    if (!(file.Characteristics & IMAGE_FILE_DLL)) {
        error = "Image is not a DLL";
        return false;
    }
    const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(file);
    IMAGE_OPTIONAL_HEADER64 optional{};
    if (file.SizeOfOptionalHeader < sizeof(optional) ||
        !in_bounds(optional_offset, file.SizeOfOptionalHeader, bytes.size()) ||
        !read(bytes, optional_offset, optional) || optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = "Invalid or truncated PE32+ optional header";
        return false;
    }
    if (optional.SizeOfImage == 0 || optional.SizeOfImage > 1024u * 1024u * 1024u ||
        optional.SizeOfHeaders > bytes.size() || optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        error = "Invalid PE image dimensions or data directories";
        return false;
    }
    const size_t section_offset = optional_offset + file.SizeOfOptionalHeader;
    if (!in_bounds(section_offset, static_cast<size_t>(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), bytes.size())) {
        error = "Truncated section table";
        return false;
    }

    report.machine = file.Machine;
    report.image_size = optional.SizeOfImage;
    report.entry_point = optional.AddressOfEntryPoint;
    report.preferred_base = optional.ImageBase;
    std::vector<IMAGE_SECTION_HEADER> headers;
    for (size_t i = 0; i < file.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        read(bytes, section_offset + i * sizeof(section), section);
        if (!in_bounds(section.PointerToRawData, section.SizeOfRawData, bytes.size()) ||
            section.VirtualAddress > optional.SizeOfImage ||
            (std::max)(section.Misc.VirtualSize, section.SizeOfRawData) > optional.SizeOfImage - section.VirtualAddress) {
            error = "Section raw or virtual range exceeds image bounds";
            return false;
        }
        const auto name_end = std::find(section.Name, section.Name + IMAGE_SIZEOF_SHORT_NAME, 0);
        report.sections.push_back({
            std::string(reinterpret_cast<const char*>(section.Name),
                        reinterpret_cast<const char*>(name_end)),
            section.VirtualAddress, section.Misc.VirtualSize, section.PointerToRawData,
            section.SizeOfRawData, section.Characteristics
        });
        headers.push_back(section);
    }

    const auto rva_to_offset = [&](uint32_t rva, size_t length, size_t& offset) {
        if (rva < optional.SizeOfHeaders && in_bounds(rva, length, bytes.size()) &&
            length <= optional.SizeOfHeaders - rva) {
            offset = rva;
            return true;
        }
        for (const auto& section : headers) {
            if (rva >= section.VirtualAddress && rva - section.VirtualAddress <= section.SizeOfRawData &&
                length <= section.SizeOfRawData - (rva - section.VirtualAddress)) {
                offset = static_cast<size_t>(section.PointerToRawData) + rva - section.VirtualAddress;
                return in_bounds(offset, length, bytes.size());
            }
        }
        return false;
    };

    const auto& import_dir = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress != 0 || import_dir.Size != 0) {
        size_t offset = 0;
        if (import_dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !rva_to_offset(import_dir.VirtualAddress, import_dir.Size, offset)) {
            error = "Import directory exceeds file bounds";
            return false;
        }
        bool terminated = false;
        for (size_t pos = 0; pos + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= import_dir.Size;
             pos += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            read(bytes, offset + pos, descriptor);
            if (descriptor.Name == 0) { terminated = true; break; }
            size_t name_offset = 0;
            std::string name;
            if (!rva_to_offset(descriptor.Name, 1, name_offset) ||
                !read_string(bytes, name_offset, name)) {
                error = "Invalid import DLL name";
                return false;
            }
            report.imports.push_back(name);
        }
        if (!terminated) { error = "Unterminated import directory"; return false; }
    }

    const auto& reloc_dir = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress != 0 || reloc_dir.Size != 0) {
        size_t offset = 0;
        if (!rva_to_offset(reloc_dir.VirtualAddress, reloc_dir.Size, offset)) {
            error = "Relocation directory exceeds file bounds";
            return false;
        }
        size_t pos = 0;
        while (pos < reloc_dir.Size) {
            IMAGE_BASE_RELOCATION block{};
            if (reloc_dir.Size - pos < sizeof(block) || !read(bytes, offset + pos, block) ||
                block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > reloc_dir.Size - pos ||
                (block.SizeOfBlock - sizeof(block)) % sizeof(WORD) != 0) {
                error = "Invalid relocation block";
                return false;
            }
            ++report.relocation_blocks;
            report.relocation_entries += (block.SizeOfBlock - sizeof(block)) / sizeof(WORD);
            pos += block.SizeOfBlock;
        }
    }
    return true;
}

} // namespace PeInspector

#endif
