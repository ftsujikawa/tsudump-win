#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <capstone/capstone.h>

void dump_text_section_bytes(FILE* file, DWORD section_offset, WORD number_of_sections) {
    IMAGE_SECTION_HEADER section;
    int i;
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (memcmp(section.Name, ".text", 5) == 0) {
            unsigned char* code;
            DWORD j;
            printf("=== .text セクション バイトダンプ ===\n");
            code = malloc(section.SizeOfRawData);
            if (code == NULL) {
                fprintf(stderr, "メモリ確保に失敗しました\n");
                return;
            }
            fseek(file, section.PointerToRawData, SEEK_SET);
            if (fread(code, 1, section.SizeOfRawData, file) != section.SizeOfRawData) {
                fprintf(stderr, "データ読み込みに失敗しました\n");
                free(code);
                return;
            }
            for (j = 0; j < section.SizeOfRawData; j++) {
                if (j % 16 == 0) printf("\n%08X: ", section.VirtualAddress + j);
                printf("%02X ", code[j]);
            }
            printf("\n\n");
            free(code);
            break;
        }
    }
}

void disassemble_text_section_capstone(FILE* file, DWORD section_offset, WORD number_of_sections, uint64_t image_base, int is_64bit) {
    IMAGE_SECTION_HEADER section;
    int i;
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (memcmp(section.Name, ".text", 5) == 0) {
            unsigned char* code = (unsigned char*)malloc(section.SizeOfRawData);
            if (!code) {
                fprintf(stderr, "メモリ確保に失敗しました\n");
                return;
            }
            if (fseek(file, section.PointerToRawData, SEEK_SET) != 0 ||
                fread(code, 1, section.SizeOfRawData, file) != section.SizeOfRawData) {
                fprintf(stderr, "データ読み込みに失敗しました\n");
                free(code);
                return;
            }

            printf("=== .text セクション 逆アセンブル (Capstone) ===\n");
            uint64_t start_va = image_base + (uint64_t)section.VirtualAddress;
            printf("RVA: 0x%08X  開始VA: 0x%016llX  サイズ: 0x%08X  オフセット: 0x%08X\n\n",
                   section.VirtualAddress, (unsigned long long)start_va, section.SizeOfRawData, section.PointerToRawData);

            csh handle;
            cs_insn* insn = NULL;
            cs_err err;
            cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
            err = cs_open(CS_ARCH_X86, mode, &handle);
            if (err != CS_ERR_OK) {
                fprintf(stderr, "Capstone初期化に失敗しました: %d\n", err);
                free(code);
                return;
            }
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

            size_t count = cs_disasm(handle, code, section.SizeOfRawData,
                                     start_va, 0, &insn);
            if (count > 0) {
                for (size_t j = 0; j < count; j++) {
                    // アドレス
                    printf("0x%016" PRIx64 ": ", (uint64_t)insn[j].address);
                    // 命令バイト（最大10バイト表示、??埋め???
                    int byte_count = (int)insn[j].size;
                    if (byte_count > 10) byte_count = 10;
                    for (int b = 0; b < byte_count; b++) {
                        printf("%02X ", insn[j].bytes[b]);
                    }
                    // パディング???10バイト???の??: 3*10=30???
                    for (int p = byte_count; p < 10; p++) {
                        printf("   ");
                    }
                    // 命令
                    if (insn[j].op_str && insn[j].op_str[0])
                        printf("  %s %s\n", insn[j].mnemonic, insn[j].op_str);
                    else
                        printf("  %s\n", insn[j].mnemonic);
                }
                cs_free(insn, count);
            } else {
                printf("??アセンブルに失敗しました??\n");
            }
            cs_close(&handle);
            printf("\n");
            free(code);
            break;
        }
    }
}



void print_section_headers(FILE* file, DWORD section_offset, WORD number_of_sections) {
    printf("=== Section Headers ===\n");
    IMAGE_SECTION_HEADER section;
    // セクション名???最大長は8????
    char name[9];
    int i;
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        memcpy(name, section.Name, 8);
        name[8] = '\0';
        printf("[%d] Name: %s\n", i + 1, name);
        printf("    VirtualSize:      0x%08X\n", section.Misc.VirtualSize);
        printf("    VirtualAddress:   0x%08X\n", section.VirtualAddress);
        printf("    SizeOfRawData:    0x%08X\n", section.SizeOfRawData);
        printf("    PointerToRawData: 0x%08X\n", section.PointerToRawData);
        printf("    Characteristics:  0x%08X\n", section.Characteristics);
    }
    printf("\n");
}

void print_dos_header(IMAGE_DOS_HEADER* dos_header) {
    printf("=== DOS Header ===\n");
    printf("e_magic:    0x%04X (%s)\n", dos_header->e_magic, 
           dos_header->e_magic == IMAGE_DOS_SIGNATURE ? "MZ" : "Invalid");
    printf("e_cblp:     %d\n", dos_header->e_cblp);
    printf("e_cp:       %d\n", dos_header->e_cp);
    printf("e_crlc:     %d\n", dos_header->e_crlc);
    printf("e_cparhdr:  %d\n", dos_header->e_cparhdr);
    printf("e_minalloc: %d\n", dos_header->e_minalloc);
    printf("e_maxalloc: %d\n", dos_header->e_maxalloc);
    printf("e_ss:       0x%04X\n", dos_header->e_ss);
    printf("e_sp:       0x%04X\n", dos_header->e_sp);
    printf("e_csum:     0x%04X\n", dos_header->e_csum);
    printf("e_ip:       0x%04X\n", dos_header->e_ip);
    printf("e_cs:       0x%04X\n", dos_header->e_cs);
    printf("e_lfarlc:   0x%04X\n", dos_header->e_lfarlc);
    printf("e_ovno:     %d\n", dos_header->e_ovno);
    printf("e_oemid:    %d\n", dos_header->e_oemid);
    printf("e_oeminfo:  %d\n", dos_header->e_oeminfo);
    printf("e_lfanew:   0x%08X (PE Header offset)\n", dos_header->e_lfanew);
    printf("\n");
}

void print_nt_headers(IMAGE_NT_HEADERS32* nt_headers) {
    printf("=== NT Headers ===\n");
    printf("Signature: 0x%08X (%s)\n", nt_headers->Signature,
           nt_headers->Signature == IMAGE_NT_SIGNATURE ? "PE" : "Invalid");
    printf("\n");
}

void print_file_header(IMAGE_FILE_HEADER* file_header) {
    printf("=== File Header ===\n");
    printf("Machine:              0x%04X (", file_header->Machine);
    switch(file_header->Machine) {
        case IMAGE_FILE_MACHINE_I386:
            printf("i386");
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf("AMD64");
            break;
        case IMAGE_FILE_MACHINE_ARM:
            printf("ARM");
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            printf("ARM64");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf(")\n");
    printf("NumberOfSections:     %d\n", file_header->NumberOfSections);
    // TimeDateStampを日本時間で表示
    time_t timestamp = (time_t)file_header->TimeDateStamp;
    struct tm local_tm;
    localtime_s(&local_tm, &timestamp);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y/%m/%d %H:%M:%S", &local_tm);
    printf("TimeDateStamp:        0x%08X (%s)\n", file_header->TimeDateStamp, timebuf);
    printf("PointerToSymbolTable: 0x%08X\n", file_header->PointerToSymbolTable);
    printf("NumberOfSymbols:      %d\n", file_header->NumberOfSymbols);
    printf("SizeOfOptionalHeader: %d\n", file_header->SizeOfOptionalHeader);
    printf("Characteristics:      0x%04X\n", file_header->Characteristics);
    
    // Characteristics flags
    if (file_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("  - Executable image\n");
    if (file_header->Characteristics & IMAGE_FILE_DLL)
        printf("  - DLL\n");
    if (file_header->Characteristics & IMAGE_FILE_SYSTEM)
        printf("  - System file\n");
    if (file_header->Characteristics & IMAGE_FILE_32BIT_MACHINE)
        printf("  - 32-bit machine\n");
    if (file_header->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        printf("  - Large address aware\n");
    printf("\n");
}

void print_optional_header(IMAGE_OPTIONAL_HEADER32* opt_header) {
    printf("=== Optional Header ===\n");
    printf("Magic:                    0x%04X (%s)\n", opt_header->Magic,
           opt_header->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "PE32" :
           opt_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "Unknown");
    printf("MajorLinkerVersion:       %d\n", opt_header->MajorLinkerVersion);
    printf("MinorLinkerVersion:       %d\n", opt_header->MinorLinkerVersion);
    printf("SizeOfCode:               0x%08X (%d bytes)\n", opt_header->SizeOfCode, opt_header->SizeOfCode);
    printf("SizeOfInitializedData:    0x%08X (%d bytes)\n", opt_header->SizeOfInitializedData, opt_header->SizeOfInitializedData);
    printf("SizeOfUninitializedData:  0x%08X (%d bytes)\n", opt_header->SizeOfUninitializedData, opt_header->SizeOfUninitializedData);
    printf("AddressOfEntryPoint:      0x%08X\n", opt_header->AddressOfEntryPoint);
    printf("BaseOfCode:               0x%08X\n", opt_header->BaseOfCode);
    printf("ImageBase:                0x%08llX\n", (unsigned long long)opt_header->ImageBase);
    printf("SectionAlignment:         0x%08X\n", opt_header->SectionAlignment);
    printf("FileAlignment:            0x%08X\n", opt_header->FileAlignment);
    printf("MajorOperatingSystemVersion: %d\n", opt_header->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %d\n", opt_header->MinorOperatingSystemVersion);
    printf("MajorImageVersion:        %d\n", opt_header->MajorImageVersion);
    printf("MinorImageVersion:        %d\n", opt_header->MinorImageVersion);
    printf("MajorSubsystemVersion:    %d\n", opt_header->MajorSubsystemVersion);
    printf("MinorSubsystemVersion:    %d\n", opt_header->MinorSubsystemVersion);
    printf("SizeOfImage:              0x%08X (%d bytes)\n", opt_header->SizeOfImage, opt_header->SizeOfImage);
    printf("SizeOfHeaders:            0x%08X (%d bytes)\n", opt_header->SizeOfHeaders, opt_header->SizeOfHeaders);
    printf("CheckSum:                 0x%08X\n", opt_header->CheckSum);
    printf("Subsystem:                %d (", opt_header->Subsystem);
    switch(opt_header->Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:
            printf("Native");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            printf("Windows GUI");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            printf("Windows Console");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf(")\n");
    printf("DllCharacteristics:       0x%04X\n", opt_header->DllCharacteristics);
    printf("SizeOfStackReserve:       0x%08llX\n", (unsigned long long)opt_header->SizeOfStackReserve);
    printf("SizeOfStackCommit:        0x%08llX\n", (unsigned long long)opt_header->SizeOfStackCommit);
    printf("SizeOfHeapReserve:        0x%08llX\n", (unsigned long long)opt_header->SizeOfHeapReserve);
    printf("SizeOfHeapCommit:         0x%08llX\n", (unsigned long long)opt_header->SizeOfHeapCommit);
    printf("NumberOfRvaAndSizes:      %d\n", opt_header->NumberOfRvaAndSizes);
    printf("\n");
}

void print_data_directories(IMAGE_DATA_DIRECTORY* data_dirs, DWORD count) {
    printf("=== Data Directories ===\n");
    const char* dir_names[] = {
        "Export Table",
        "Import Table", 
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "COM+ Runtime Header",
        "Reserved"
    };
    
    for (DWORD i = 0; i < count && i < 16; i++) {
        if (data_dirs[i].VirtualAddress != 0 || data_dirs[i].Size != 0) {
            printf("%-25s: RVA=0x%08X Size=0x%08X (%d bytes)\n", 
                   dir_names[i], data_dirs[i].VirtualAddress, 
                   data_dirs[i].Size, data_dirs[i].Size);
        }
    }
    printf("\n");
}

void print_optional_header64(IMAGE_OPTIONAL_HEADER64* opt_header) {
    printf("=== Optional Header (64bit) ===\n");
    printf("Magic:                    0x%04X (%s)\n", opt_header->Magic,
           opt_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+" : "Unknown");
    printf("MajorLinkerVersion:       %d\n", opt_header->MajorLinkerVersion);
    printf("MinorLinkerVersion:       %d\n", opt_header->MinorLinkerVersion);
    printf("SizeOfCode:               0x%08X (%d bytes)\n", opt_header->SizeOfCode, opt_header->SizeOfCode);
    printf("SizeOfInitializedData:    0x%08X (%d bytes)\n", opt_header->SizeOfInitializedData, opt_header->SizeOfInitializedData);
    printf("SizeOfUninitializedData:  0x%08X (%d bytes)\n", opt_header->SizeOfUninitializedData, opt_header->SizeOfUninitializedData);
    printf("AddressOfEntryPoint:      0x%08X\n", opt_header->AddressOfEntryPoint);
    printf("BaseOfCode:               0x%08X\n", opt_header->BaseOfCode);
    printf("ImageBase:                0x%016llX\n", (unsigned long long)opt_header->ImageBase);
    printf("SectionAlignment:         0x%08X\n", opt_header->SectionAlignment);
    printf("FileAlignment:            0x%08X\n", opt_header->FileAlignment);
    printf("MajorOperatingSystemVersion: %d\n", opt_header->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %d\n", opt_header->MinorOperatingSystemVersion);
    printf("MajorImageVersion:        %d\n", opt_header->MajorImageVersion);
    printf("MinorImageVersion:        %d\n", opt_header->MinorImageVersion);
    printf("MajorSubsystemVersion:    %d\n", opt_header->MajorSubsystemVersion);
    printf("MinorSubsystemVersion:    %d\n", opt_header->MinorSubsystemVersion);
    printf("SizeOfImage:              0x%08X (%d bytes)\n", opt_header->SizeOfImage, opt_header->SizeOfImage);
    printf("SizeOfHeaders:            0x%08X (%d bytes)\n", opt_header->SizeOfHeaders, opt_header->SizeOfHeaders);
    printf("CheckSum:                 0x%08X\n", opt_header->CheckSum);
    printf("Subsystem:                %d (", opt_header->Subsystem);
    switch(opt_header->Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:
            printf("Native");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            printf("Windows GUI");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            printf("Windows Console");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf(")\n");
    printf("DllCharacteristics:       0x%04X\n", opt_header->DllCharacteristics);
    printf("SizeOfStackReserve:       0x%016llX\n", (unsigned long long)opt_header->SizeOfStackReserve);
    printf("SizeOfStackCommit:        0x%016llX\n", (unsigned long long)opt_header->SizeOfStackCommit);
    printf("SizeOfHeapReserve:        0x%016llX\n", (unsigned long long)opt_header->SizeOfHeapReserve);
    printf("SizeOfHeapCommit:         0x%016llX\n", (unsigned long long)opt_header->SizeOfHeapCommit);
    printf("NumberOfRvaAndSizes:      %d\n", opt_header->NumberOfRvaAndSizes);
    printf("\n");
}

int analyze_pe_file(const char* filename) {
    FILE* file;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS32 nt_headers;
    DWORD section_offset;
    long opt_hdr_pos;
    WORD magic;
    uint64_t image_base_val;
    int is64;
    
    file = fopen(filename, "rb");
    if (!file) {
        printf("エラー: ファイル '%s' を開けません\n", filename);
        return 1;
    }
    
    // DOS Header読み込み
    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        printf("エラー: DOS Headerの読み込みに失敗しました\n");
        fclose(file);
        return 1;
    }
    
    // MZシグネチャチェ??ク
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("エラー: 有効なPEファイルではありません (MZシグネチャが見つかりません)\n");
        fclose(file);
        return 1;
    }
    
    print_dos_header(&dos_header);
    
    // PE Headerの位置に移??
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("エラー: PE Headerの位置に移動できません\n");
        fclose(file);
        return 1;
    }
    
    // NT Headers読み込み
    if (fread(&nt_headers, sizeof(IMAGE_NT_HEADERS32), 1, file) != 1) {
        printf("エラー: NT Headersの読み込みに失敗しました\n");
        fclose(file);
        return 1;
    }
    
    // PEシグネチャチェ??ク
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        printf("エラー: 有効なPEシグネチャが見つかりません\n");
        fclose(file);
        return 1;
    }
    
    print_nt_headers(&nt_headers);
    print_file_header(&nt_headers.FileHeader);
    // Optional HeaderのMagicで32/64を判定
    if (nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // 64bit Optional Header を読み込んで表示
        long opt_hdr_pos_early = (long)dos_header.e_lfanew + (long)sizeof(DWORD) + (long)sizeof(IMAGE_FILE_HEADER);
        if (fseek(file, opt_hdr_pos_early, SEEK_SET) != 0) {
            printf("エラー: Optional Header64の位置に移動できません\n");
            fclose(file);
            return 1;
        }
        IMAGE_OPTIONAL_HEADER64 opt64_early;
        if (fread(&opt64_early, sizeof(IMAGE_OPTIONAL_HEADER64), 1, file) != 1) {
            printf("エラー: Optional Header64の読み込みに失敗しました\n");
            fclose(file);
            return 1;
        }
        print_optional_header64(&opt64_early);
        print_data_directories(opt64_early.DataDirectory, opt64_early.NumberOfRvaAndSizes);
    } else {
        print_optional_header(&nt_headers.OptionalHeader);
        print_data_directories(nt_headers.OptionalHeader.DataDirectory,
                               nt_headers.OptionalHeader.NumberOfRvaAndSizes);
    }

    // セクションヘッダー表示
    section_offset = dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader;
    print_section_headers(file, section_offset, nt_headers.FileHeader.NumberOfSections);

    // Optional HeaderのMagicを確認してImageBaseとビット数を決定
    opt_hdr_pos = (long)dos_header.e_lfanew + (long)sizeof(DWORD) + (long)sizeof(IMAGE_FILE_HEADER);
    if (fseek(file, opt_hdr_pos, SEEK_SET) != 0) {
        printf("エラー: Optional Header位置に移動できません\n");
        fclose(file);
        return 1;
    }
    magic = 0;
    if (fread(&magic, sizeof(WORD), 1, file) != 1) {
        printf("エラー: Optional HeaderのMagic読み込みに失敗しました\n");
        fclose(file);
        return 1;
    }
    image_base_val = 0;
    is64 = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // 64bit Optional Header を読み込む（ImageBase取得のみ）
        if (fseek(file, opt_hdr_pos, SEEK_SET) != 0) {
            printf("エラー: Optional Header64の位置に移動できません\n");
            fclose(file);
            return 1;
        }
        IMAGE_OPTIONAL_HEADER64 opt64;
        if (fread(&opt64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, file) != 1) {
            printf("エラー: Optional Header64の読み込みに失敗しました\n");
            fclose(file);
            return 1;
        }
        image_base_val = (uint64_t)opt64.ImageBase;
        is64 = 1;
    } else {
        // 32bit Optional Header（既にnt_headersに読み込まれている）
        image_base_val = (uint64_t)nt_headers.OptionalHeader.ImageBase;
        is64 = 0;
    }

    // .text セクション逆アセンブル（Capstone）
    disassemble_text_section_capstone(file, section_offset, (WORD)nt_headers.FileHeader.NumberOfSections, image_base_val, is64);
    
    fclose(file);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("PE Header Dump Tool\n");
    printf("===================\n\n");
    
    if (argc != 2) {
        printf("使用方??: %s <PEファイル>\n", argv[0]);
        printf("??: %s notepad.exe\n", argv[0]);
        return 1;
    }
    
    printf("ファイル: %s\n\n", argv[1]);
    
    int result = analyze_pe_file(argv[1]);
    if (result == 0) {
        printf("PE Header解析が完??しました??\n");
    }
    
    return result;
}