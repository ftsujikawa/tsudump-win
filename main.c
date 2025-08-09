#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

void simple_disassemble_text_section(FILE* file, DWORD section_offset, WORD number_of_sections) {
    IMAGE_SECTION_HEADER section;
    int i;
    unsigned char* code;
    DWORD addr;
    DWORD j;
    unsigned char b;
    
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (memcmp(section.Name, ".text", 5) == 0) {
            printf("=== .text セクション 簡易逆アセンブル ===\n");
            code = malloc(section.SizeOfRawData);
            fseek(file, section.PointerToRawData, SEEK_SET);
            fread(code, 1, section.SizeOfRawData, file);
            addr = section.VirtualAddress;
            for (j = 0; j < section.SizeOfRawData; ) {
                printf("%08X: ", addr + j);
                b = code[j];
                
                // 境界チェック付きの安全な逆アセンブル
                if (b == 0xC3) { 
                    printf("RET\n"); 
                    j += 1; 
                }
                else if (b == 0xE8) { 
                    if (j + 4 < section.SizeOfRawData) {
                        printf("CALL 0x%02X%02X%02X%02X\n", code[j+4], code[j+3], code[j+2], code[j+1]); 
                        j += 5; 
                    } else {
                        printf("CALL (不完全)\n");
                        j += 1;
                    }
                }
                else if (b == 0xE9) { 
                    if (j + 4 < section.SizeOfRawData) {
                        printf("JMP 0x%02X%02X%02X%02X\n", code[j+4], code[j+3], code[j+2], code[j+1]); 
                        j += 5; 
                    } else {
                        printf("JMP (不完全)\n");
                        j += 1;
                    }
                }
                else if (b == 0xEB) { 
                    if (j + 1 < section.SizeOfRawData) {
                        printf("JMP SHORT 0x%02X\n", code[j+1]); 
                        j += 2; 
                    } else {
                        printf("JMP SHORT (不完全)\n");
                        j += 1;
                    }
                }
                else if (b == 0x90) { 
                    printf("NOP\n"); 
                    j += 1; 
                }
                else if ((b & 0xF0) == 0xB0) { 
                    if (j + 1 < section.SizeOfRawData) {
                        printf("MOV AL, 0x%02X\n", code[j+1]); 
                        j += 2; 
                    } else {
                        printf("MOV AL (不完全)\n");
                        j += 1;
                    }
                }
                else if ((b & 0xF8) == 0xB8) { 
                    if (j + 4 < section.SizeOfRawData) {
                        printf("MOV EAX, 0x%02X%02X%02X%02X\n", code[j+4], code[j+3], code[j+2], code[j+1]); 
                        j += 5; 
                    } else {
                        printf("MOV EAX (不完全)\n");
                        j += 1;
                    }
                }
                else { 
                    printf("DB 0x%02X\n", b); 
                    j += 1; 
                }
                
                // 安全チェック：jが進歩しない場合の強制終了
                if (j >= section.SizeOfRawData) {
                    break;
                }
            }
            free(code);
            break;
        }
    }
}

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
            fseek(file, section.PointerToRawData, SEEK_SET);
            fread(code, 1, section.SizeOfRawData, file);
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

// x86命令の詳細な逆アセンブル（出力制限付き）
void disassemble_text_section(FILE* file, DWORD section_offset, WORD number_of_sections) {
    const DWORD MAX_INSTRUCTIONS = 100; // 最大表示命令数を削減（安全対策）
    IMAGE_SECTION_HEADER section;
    int i;
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        
        if (memcmp(section.Name, ".text", 5) == 0) {
            printf("=== .text セクション 詳細逆アセンブル ===\n");
            printf("仮想アドレス: 0x%08X\n", section.VirtualAddress);
            printf("サイズ: 0x%08X バイト\n", section.SizeOfRawData);
            printf("ファイル内オフセット: 0x%08X\n\n", section.PointerToRawData);
            
            unsigned char* code = malloc(section.SizeOfRawData);
            if (!code) {
                printf("エラー: メモリ割り当てに失敗しました\n");
                return;
            }
            
            fseek(file, section.PointerToRawData, SEEK_SET);
            fread(code, 1, section.SizeOfRawData, file);
            
            DWORD base_addr;
            DWORD pos;
            DWORD instruction_count;
            int bytes_shown;
            int instruction_len;
            unsigned char opcode;
            DWORD old_pos;
            
            base_addr = section.VirtualAddress;
            pos = 0;
            instruction_count = 0;
            
            while (pos < section.SizeOfRawData && instruction_count < MAX_INSTRUCTIONS) {
                // 追加の安全チェック：posが範囲外の場合は強制終了
                if (pos >= section.SizeOfRawData) {
                    break;
                }
                
                printf("%08X: ", base_addr + pos);
                
                // バイト表示（最大8バイト）
                bytes_shown = 0;
                instruction_len = 1; // デフォルト値を1に設定（安全対策）
                old_pos = pos; // 進捗チェック用
                
                opcode = code[pos];
                
                // 命令長の判定と逆アセンブル
                if (opcode == 0x90) {
                    printf("90           NOP\n");
                    instruction_len = 1;
                }
                else if (opcode == 0xC3) {
                    printf("C3           RET\n");
                    instruction_len = 1;
                }
                else if (opcode == 0xCC) {
                    printf("CC           INT3\n");
                    instruction_len = 1;
                }
                else if (opcode == 0xE8) {
                    // CALL rel32
                    if (pos + 4 < section.SizeOfRawData) {
                        DWORD offset;
                        offset = *(DWORD*)(code + pos + 1);
                        printf("E8 %02X %02X %02X %02X CALL 0x%08X\n", 
                               code[pos+1], code[pos+2], code[pos+3], code[pos+4],
                               base_addr + pos + 5 + (int)offset);
                        instruction_len = 5;
                    } else {
                        printf("E8           CALL (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0xE9) {
                    // JMP rel32
                    if (pos + 4 < section.SizeOfRawData) {
                        DWORD offset;
                        offset = *(DWORD*)(code + pos + 1);
                        printf("E9 %02X %02X %02X %02X JMP 0x%08X\n", 
                               code[pos+1], code[pos+2], code[pos+3], code[pos+4],
                               base_addr + pos + 5 + (int)offset);
                        instruction_len = 5;
                    } else {
                        printf("E9           JMP (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0xEB) {
                    // JMP rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("EB %02X        JMP SHORT 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("EB           JMP SHORT (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if ((opcode & 0xF8) == 0x50) {
                    // PUSH reg32
                    printf("%02X           PUSH %s\n", opcode, 
                           (opcode == 0x50) ? "EAX" : (opcode == 0x51) ? "ECX" : 
                           (opcode == 0x52) ? "EDX" : (opcode == 0x53) ? "EBX" :
                           (opcode == 0x54) ? "ESP" : (opcode == 0x55) ? "EBP" :
                           (opcode == 0x56) ? "ESI" : "EDI");
                    instruction_len = 1;
                }
                else if ((opcode & 0xF8) == 0x58) {
                    // POP reg32
                    printf("%02X           POP %s\n", opcode,
                           (opcode == 0x58) ? "EAX" : (opcode == 0x59) ? "ECX" : 
                           (opcode == 0x5A) ? "EDX" : (opcode == 0x5B) ? "EBX" :
                           (opcode == 0x5C) ? "ESP" : (opcode == 0x5D) ? "EBP" :
                           (opcode == 0x5E) ? "ESI" : "EDI");
                    instruction_len = 1;
                }
                else if ((opcode & 0xF8) == 0xB8) {
                    // MOV reg32, imm32
                    if (pos + 4 < section.SizeOfRawData) {
                        DWORD imm;
                        imm = *(DWORD*)(code + pos + 1);
                        printf("%02X %02X %02X %02X %02X MOV %s, 0x%08X\n", 
                               opcode, code[pos+1], code[pos+2], code[pos+3], code[pos+4],
                               (opcode == 0xB8) ? "EAX" : (opcode == 0xB9) ? "ECX" : 
                               (opcode == 0xBA) ? "EDX" : (opcode == 0xBB) ? "EBX" :
                               (opcode == 0xBC) ? "ESP" : (opcode == 0xBD) ? "EBP" :
                               (opcode == 0xBE) ? "ESI" : "EDI", imm);
                        instruction_len = 5;
                    } else {
                        printf("%02X           MOV (不完全)\n", opcode);
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x8B) {
                    // MOV reg, r/m (簡易版)
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm;
                        modrm = code[pos + 1];
                        printf("%02X %02X        MOV (ModR/M: 0x%02X)\n", opcode, modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("%02X           MOV (不完全)\n", opcode);
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x89) {
                    // MOV r/m, reg (簡易版)
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm;
                        modrm = code[pos + 1];
                        printf("%02X %02X        MOV (ModR/M: 0x%02X)\n", opcode, modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("%02X           MOV (不完全)\n", opcode);
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x83) {
                    // 算術演算 imm8
                    if (pos + 2 < section.SizeOfRawData) {
                        unsigned char modrm;
                        unsigned char imm8;
                        modrm = code[pos + 1];
                        imm8 = code[pos + 2];
                        printf("%02X %02X %02X     ADD/OR/ADC/SBB/AND/SUB/XOR/CMP (ModR/M: 0x%02X, imm8: 0x%02X)\n", 
                               opcode, modrm, imm8, modrm, imm8);
                        instruction_len = 3;
                    } else {
                        printf("%02X           算術演算 (不完全)\n", opcode);
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x74) {
                    // JZ/JE rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("74 %02X        JZ 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("74           JZ (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x75) {
                    // JNZ/JNE rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("75 %02X        JNZ 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("75           JNZ (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x72) {
                    // JB/JC rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("72 %02X        JB 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("72           JB (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x73) {
                    // JAE/JNC rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("73 %02X        JAE 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("73           JAE (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x76) {
                    // JBE/JNA rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("76 %02X        JBE 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("76           JBE (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x77) {
                    // JA/JNBE rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("77 %02X        JA 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("77           JA (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x78) {
                    // JS rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset;
                        offset = (signed char)code[pos + 1];
                        printf("78 %02X        JS 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("78           JS (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x79) {
                    // JNS rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset = (signed char)code[pos + 1];
                        printf("79 %02X        JNS 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("79           JNS (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x7C) {
                    // JL/JNGE rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset = (signed char)code[pos + 1];
                        printf("7C %02X        JL 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("7C           JL (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x7D) {
                    // JGE/JNL rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset = (signed char)code[pos + 1];
                        printf("7D %02X        JGE 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("7D           JGE (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x7E) {
                    // JLE/JNG rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset = (signed char)code[pos + 1];
                        printf("7E %02X        JLE 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("7E           JLE (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x7F) {
                    // JG/JNLE rel8
                    if (pos + 1 < section.SizeOfRawData) {
                        signed char offset = (signed char)code[pos + 1];
                        printf("7F %02X        JG 0x%08X\n", 
                               code[pos+1], base_addr + pos + 2 + offset);
                        instruction_len = 2;
                    } else {
                        printf("7F           JG (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x68) {
                    // PUSH imm32
                    if (pos + 4 < section.SizeOfRawData) {
                        DWORD imm = *(DWORD*)(code + pos + 1);
                        printf("68 %02X %02X %02X %02X PUSH 0x%08X\n", 
                               code[pos+1], code[pos+2], code[pos+3], code[pos+4], imm);
                        instruction_len = 5;
                    } else {
                        printf("68           PUSH (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x6A) {
                    // PUSH imm8
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char imm8 = code[pos + 1];
                        printf("6A %02X        PUSH 0x%02X\n", imm8, imm8);
                        instruction_len = 2;
                    } else {
                        printf("6A           PUSH (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x85) {
                    // TEST reg, r/m
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("85 %02X        TEST (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("85           TEST (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x3B) {
                    // CMP reg, r/m
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("3B %02X        CMP (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("3B           CMP (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x39) {
                    // CMP r/m, reg
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("39 %02X        CMP (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("39           CMP (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x01) {
                    // ADD r/m, reg
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("01 %02X        ADD (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("01           ADD (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x03) {
                    // ADD reg, r/m
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("03 %02X        ADD (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("03           ADD (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x29) {
                    // SUB r/m, reg
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("29 %02X        SUB (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("29           SUB (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else if (opcode == 0x2B) {
                    // SUB reg, r/m
                    if (pos + 1 < section.SizeOfRawData) {
                        unsigned char modrm = code[pos + 1];
                        printf("2B %02X        SUB (ModR/M: 0x%02X)\n", modrm, modrm);
                        instruction_len = 2;
                    } else {
                        printf("2B           SUB (不完全)\n");
                        instruction_len = 1;
                    }
                }
                else {
                    // 不明な命令
                    printf("%02X           DB 0x%02X\n", opcode, opcode);
                    instruction_len = 1;
                }
                
                // 安全チェック：instruction_lenが0の場合は強制的に1にする
                if (instruction_len <= 0) {
                    printf("WARNING: Invalid instruction length, forcing to 1\n");
                    instruction_len = 1;
                }
                
                // posを進める前に最終チェック
                pos += instruction_len;
                instruction_count++;
                
                // 無限ループ防止：posが進歩していない場合は強制終了
                if (pos <= old_pos) {
                    printf("ERROR: Position not advancing (pos=%d, old_pos=%d), breaking loop\n", pos, old_pos);
                    break;
                }
                
                // 追加の安全チェック：posが範囲を超えた場合
                if (pos > section.SizeOfRawData) {
                    break;
                }
                
                // 緊急ブレーキ：instruction_countが異常に大きくなった場合
                if (instruction_count > MAX_INSTRUCTIONS * 2) {
                    printf("ERROR: Instruction count exceeded safety limit, breaking loop\n");
                    break;
                }
            }
            
            if (instruction_count >= MAX_INSTRUCTIONS) {
                printf("... (出力を%d命令で制限しました。全体: %d バイト)\n", MAX_INSTRUCTIONS, section.SizeOfRawData);
            }
            
            printf("\n");
            free(code);
            break;
        }
    }
}

void print_section_headers(FILE* file, DWORD section_offset, WORD number_of_sections) {
    printf("=== Section Headers ===\n");
    IMAGE_SECTION_HEADER section;
    // セクション名の最大長は8文字
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

int analyze_pe_file(const char* filename) {
    FILE* file;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS32 nt_headers;
    DWORD section_offset;
    
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
    
    // MZシグネチャチェック
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("エラー: 有効なPEファイルではありません (MZシグネチャが見つかりません)\n");
        fclose(file);
        return 1;
    }
    
    print_dos_header(&dos_header);
    
    // PE Headerの位置に移動
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
    
    // PEシグネチャチェック
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        printf("エラー: 有効なPEシグネチャが見つかりません\n");
        fclose(file);
        return 1;
    }
    
    print_nt_headers(&nt_headers);
    print_file_header(&nt_headers.FileHeader);
    print_optional_header(&nt_headers.OptionalHeader);
    print_data_directories(nt_headers.OptionalHeader.DataDirectory, 
                          nt_headers.OptionalHeader.NumberOfRvaAndSizes);

    // セクションヘッダー表示
    section_offset = dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader;
    print_section_headers(file, section_offset, nt_headers.FileHeader.NumberOfSections);

    // .textセクション 簡易逆アセンブル
    simple_disassemble_text_section(file, section_offset, nt_headers.FileHeader.NumberOfSections);

    // .textセクション逆アセンブル
    disassemble_text_section(file, section_offset, nt_headers.FileHeader.NumberOfSections);
    
    fclose(file);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("PE Header Dump Tool\n");
    printf("===================\n\n");
    
    if (argc != 2) {
        printf("使用方法: %s <PEファイル>\n", argv[0]);
        printf("例: %s notepad.exe\n", argv[0]);
        return 1;
    }
    
    printf("ファイル: %s\n\n", argv[1]);
    
    int result = analyze_pe_file(argv[1]);
    if (result == 0) {
        printf("PE Header解析が完了しました。\n");
    }
    
    return result;
}