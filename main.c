#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <capstone/capstone.h>

// Experimental PDB detail feature flag (temporarily disabled for build stability)
#undef TSUDUMP_PDB_EXPERIMENTAL
#define TSUDUMP_PDB_EXPERIMENTAL 1

// ===== forward declarations =====
void print_file_header(IMAGE_FILE_HEADER* file_header);
void print_section_headers(FILE* file, DWORD section_offset, WORD number_of_sections);
void print_optional_header(IMAGE_OPTIONAL_HEADER32* opt_header);
void print_optional_header64(IMAGE_OPTIONAL_HEADER64* opt_header);
void print_data_directories(IMAGE_DATA_DIRECTORY* data_dirs, DWORD count);
void disassemble_text_section_capstone(FILE* file, DWORD section_offset, WORD number_of_sections, uint64_t image_base, int is_64bit);
int analyze_obj_file(const char* filename);
int analyze_pdb_file(const char* filename);
int analyze_pe_file(const char* filename);

// DBI 詳細表示
static void print_dbi_header(const unsigned char* dbi, uint32_t dbi_size);

// Simple buffer search (memmem alternative)
static int buf_contains(const unsigned char* buf, size_t buf_len, const char* pat, size_t pat_len)
{
    size_t i;
    if (!buf || !pat || pat_len == 0 || buf_len < pat_len) return 0;
    for (i = 0; i + pat_len <= buf_len; i++) {
        if (memcmp(buf + i, pat, pat_len) == 0) return 1;
    }
    return 0;
}

// Human-readable size (B, KiB, MiB, GiB)
static void fmt_size_human(uint64_t bytes, char* out, size_t outsz)
{
    const char* unit = "B";
    double val = (double)bytes;
    if (bytes >= (1ull << 30)) { unit = "GiB"; val = val / (double)(1ull << 30); }
    else if (bytes >= (1ull << 20)) { unit = "MiB"; val = val / (double)(1ull << 20); }
    else if (bytes >= (1ull << 10)) { unit = "KiB"; val = val / (double)(1ull << 10); }
    if (out && outsz) {
        if (bytes < (1ull << 10)) {
            snprintf(out, outsz, "%" PRIu64 " %s", bytes, unit);
        } else {
            snprintf(out, outsz, "%.2f %s", val, unit);
        }
    }
}

// Simple plausibility check for DBI header
static int pdb_is_plausible_dbi_header(const unsigned char* dbi, uint32_t dbi_size, uint32_t num_streams) {
    if (!dbi || dbi_size < 64) return 0;
    int32_t verSig = 0; uint32_t verHdr=0, age=0; uint16_t gsi=0, psi=0, symrec=0;
    memcpy(&verSig, dbi + 0, 4);
    memcpy(&verHdr, dbi + 4, 4);
    memcpy(&age,    dbi + 8, 4);
    memcpy(&gsi,    dbi + 12, 2);
    memcpy(&psi,    dbi + 14, 2);
    memcpy(&symrec, dbi + 18, 2);
    if (verSig != -1) return 0; // often 0xFFFFFFFF
    // common versions (V70)
    if (!(verHdr == 19990903u || verHdr == 19990307u || verHdr == 19980316u)) return 0;
    // acceptable age range: 0..1e7
    if (age > 10000000u) return 0;
    // stream index range check
    if ((gsi != 0xFFFF && gsi >= num_streams) || (psi != 0xFFFF && psi >= num_streams)) return 0;
    if (symrec != 0xFFFF && symrec >= num_streams) return 0;
    return 1;
}

// Helper: rebuild arbitrary stream from directory
// On success returns heap buffer (caller must free). On failure returns NULL.
static unsigned char* pdb_rebuild_stream(
    FILE* f,
    const unsigned char* dir_buf,
    uint32_t dir_size,
    uint32_t num_streams,
    uint32_t page_size,
    uint32_t page_count,
    uint32_t target_index,
    uint32_t* out_size
) {
    if (out_size) *out_size = 0;
    if (!f || !dir_buf || num_streams == 0) return NULL;
    if (target_index >= num_streams) return NULL;

    const unsigned char* sizes_ptr = dir_buf + 4; // first 4 bytes: num_streams
    if (dir_size < 4u + 4u * num_streams) return NULL;
    const unsigned char* pages_ptr = sizes_ptr + 4ull * num_streams;

    // accumulate total pages before target to locate start within page array
    uint64_t total_pages_before = 0;
    uint32_t si;
    for (si = 0; si < num_streams; si++) {
        uint32_t ssz; memcpy(&ssz, sizes_ptr + 4ull * si, 4);
        if (si == target_index) {
            if (ssz == 0xFFFFFFFFu || ssz == 0) return NULL;
            uint32_t spages = (ssz + page_size - 1) / page_size;
            // validate directory area bounds
            uint64_t need_dwords = total_pages_before + spages;
            uint64_t need_bytes = need_dwords * sizeof(uint32_t);
            uint64_t have_bytes = (dir_buf + dir_size) - pages_ptr;
            if (need_bytes > have_bytes) return NULL;
            const uint32_t* plist = (const uint32_t*)(pages_ptr) + (size_t)total_pages_before;
            // validate page numbers
            uint32_t k; for (k = 0; k < spages; k++) { if (plist[k] >= page_count) return NULL; }
            // rebuild
            unsigned char* buf = (unsigned char*)malloc(ssz);
            if (!buf) return NULL;
            uint32_t copied = 0;
            for (k = 0; k < spages && copied < ssz; k++) {
                long off = (long)plist[k] * (long)page_size;
                uint32_t chunk = (ssz - copied) < page_size ? (ssz - copied) : page_size;
                if (fseek(f, off, SEEK_SET) != 0) { free(buf); return NULL; }
                if (fread(buf + copied, 1, chunk, f) != chunk) { free(buf); return NULL; }
                copied += chunk;
            }
            if (copied != ssz) { free(buf); return NULL; }
            if (out_size) *out_size = ssz;
            return buf;
        } else {
            if (ssz != 0xFFFFFFFFu && ssz > 0) {
                total_pages_before += (uint64_t)((ssz + page_size - 1) / page_size);
            }
        }
    }
    return NULL;
}

// ===== PDB/MSF (v7) minimal analyzer =====
int analyze_pdb_file(const char* filename) {
    FILE* f = fopen(filename, "rb");
    unsigned char hdr[64];
    long file_size = 0;
    if (!f) {
        printf("エラー: ファイルを開けません '%s'\n", filename);
        return 1;
    }
    // file size
    {
        long cur;
        if (fseek(f, 0, SEEK_END) != 0) { printf("エラー: ファイル末尾へのシークに失敗しました\n"); fclose(f); return 1; }
        file_size = ftell(f);
        cur = 0;
        if (fseek(f, cur, SEEK_SET) != 0) { printf("エラー: 先頭へのシークに失敗しました\n"); fclose(f); return 1; }
    }
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        printf("エラー: ヘッダ読み取りに失敗しました\n");
        fclose(f);
        return 1;
    }
    if (!buf_contains(hdr, sizeof(hdr), "Microsoft C/C++ MSF", 18)) {
        printf("[ERR] PDB/MSFシグネチャが見つかりません\n");
        fclose(f);
        return 1;
    }
    // SuperBlock fields (MSF 7.00): offsets after 32-byte magic
    // 0x20: page size (DWORD)
    // 0x24: free page map (未使用)
    // 0x28: page count (DWORD)
    // 0x2C: directory size (bytes; DWORD)
    // 0x30: reserved
    // 0x34: directory page list (DWORD[ceil(dirSize/pageSize)])
    if (sizeof(hdr) < 0x34) {
        printf("[ERR] ヘッダサイズ不足\n");
        fclose(f);
        return 1;
    }
    {
        uint32_t page_size, page_count, dir_size;
        memcpy(&page_size, hdr + 0x20, 4);
        memcpy(&page_count, hdr + 0x28, 4);
        memcpy(&dir_size,  hdr + 0x2C, 4);
        if (page_size == 0 || (page_size & (page_size - 1)) != 0 || page_size < 0x200 || page_size > 0x4000) {
            printf("[ERR] 異常な page_size=%u\n", (unsigned)page_size);
            fclose(f);
            return 1;
        }
        if (page_count == 0 || (long)page_count * (long)page_size > file_size) {
            printf("[ERR] 異常な page_count=%u (file_size=%ld)\n", (unsigned)page_count, file_size);
            fclose(f);
            return 1;
        }
        if (dir_size == 0 || dir_size > (uint32_t)(page_count * page_size)) {
            printf("[ERR] 異常な directory_size=%u\n", (unsigned)dir_size);
            fclose(f);
            return 1;
        }

        // read directory root page list from 0x34
        {
            uint32_t dir_pages = (dir_size + page_size - 1) / page_size;
            size_t list_bytes = (size_t)dir_pages * sizeof(uint32_t);
            uint32_t* dir_page_numbers = (uint32_t*)malloc(list_bytes);
            if (!dir_page_numbers && list_bytes) { printf("エラー: メモリ確保に失敗しました\n"); fclose(f); return 1; }
            // seek to 0x34
            if (fseek(f, 0x34, SEEK_SET) != 0) { printf("エラー: ディレクトリページ配列へのシークに失敗しました\n"); free(dir_page_numbers); fclose(f); return 1; }
            if (fread(dir_page_numbers, sizeof(uint32_t), dir_pages, f) != dir_pages) { printf("エラー: ディレクトリページ配列の読み取りに失敗しました\n"); free(dir_page_numbers); fclose(f); return 1; }
            // validate page numbers
            {
                uint32_t i; int ok = 1;
                for (i = 0; i < dir_pages; i++) { if (dir_page_numbers[i] >= page_count) { ok = 0; break; } }
                if (!ok) { printf("[ERR] ディレクトリページ番号が範囲外です\n"); free(dir_page_numbers); fclose(f); return 1; }
            }

            // read directory stream by concatenating pages
            unsigned char* dir_buf = (unsigned char*)malloc(dir_size);
            if (!dir_buf && dir_size) { printf("エラー: メモリ確保に失敗しました\n"); free(dir_page_numbers); fclose(f); return 1; }
            {
                uint32_t i; uint32_t copied = 0;
                for (i = 0; i < dir_pages; i++) {
                    long off = (long)dir_page_numbers[i] * (long)page_size;
                    uint32_t chunk = (dir_size - copied) < page_size ? (dir_size - copied) : page_size;
                    if (fseek(f, off, SEEK_SET) != 0) { printf("エラー: ディレクトリページへのシークに失敗しました\n"); free(dir_buf); free(dir_page_numbers); fclose(f); return 1; }
                    if (fread(dir_buf + copied, 1, chunk, f) != chunk) { printf("エラー: ディレクトリページの読み取りに失敗しました\n"); free(dir_buf); free(dir_page_numbers); fclose(f); return 1; }
                    copied += chunk;
                }
            }

            // parse directory: num streams, sizes
            printf("=== PDB/MSF 概要 ===\n");
            printf("PageSize=%u  PageCount=%u  DirectorySize=%u\n", (unsigned)page_size, (unsigned)page_count, (unsigned)dir_size);
            if (dir_size < 4) { printf("[ERR] ディレクトリサイズが小さすぎます\n"); free(dir_buf); free(dir_page_numbers); fclose(f); return 1; }
            {
                uint32_t num_streams; memcpy(&num_streams, dir_buf, 4);
                printf("Stream数: %u\n", (unsigned)num_streams);
                if (num_streams > 100000) { printf("[ERR] 異常な Stream数\n"); free(dir_buf); free(dir_page_numbers); fclose(f); return 1; }
                size_t need = 4ull + 4ull * num_streams;
                if (dir_size < need) { printf("[ERR] ディレクトリ内容が不足\n"); free(dir_buf); free(dir_page_numbers); fclose(f); return 1; }
                printf("=== 各ストリームサイズ ===\n");
                {
                    uint32_t i; const unsigned char* p = dir_buf + 4;
                    uint64_t total_bytes = 0; uint32_t non_empty = 0; uint32_t invalid = 0;
                    printf("Stream            Bytes        Human\n");
                    printf("---------------------------------------------\n");
                    for (i = 0; i < num_streams; i++) {
                        uint32_t sz; memcpy(&sz, p + 4ull * i, 4);
                        // Sanity: size must not exceed file capacity
                        if (sz != 0xFFFFFFFFu) {
                            uint64_t cap = (uint64_t)page_count * (uint64_t)page_size;
                            if ((uint64_t)sz > cap) {
                                printf("[WARN] Stream %u size too large: %u > %llu (capacity). Treating as invalid.\n",
                                       (unsigned)i, (unsigned)sz, (unsigned long long)cap);
                                sz = 0xFFFFFFFFu;
                            }
                        }
                        if (sz == 0xFFFFFFFFu) {
                            printf("[%5u] %14s %12s\n", (unsigned)i, "<無効>", "-");
                            invalid++;
                            continue;
                        }
                        if (sz > 0) { total_bytes += (uint64_t)sz; non_empty++; }
                        {
                            char h[32]; fmt_size_human((uint64_t)sz, h, sizeof(h));
                            printf("[%5u] %14u %12s\n", (unsigned)i, (unsigned)sz, h);
                        }
                    }
                    {
                        char ht[32]; fmt_size_human(total_bytes, ht, sizeof(ht));
                        printf("---------------------------------------------\n");
                        printf("Total: %u streams (valid: %u, invalid: %u)\n", (unsigned)num_streams, (unsigned)(num_streams - invalid), (unsigned)invalid);
                        printf("Non-empty streams: %u\n", (unsigned)non_empty);
                        printf("Total bytes: %" PRIu64 " (%s)\n", (uint64_t)total_bytes, ht);
                    }
                }

                // Experimental: dump heads of non-empty streams (up to 16 streams, 32 bytes each)
                if (TSUDUMP_PDB_EXPERIMENTAL) {
                    uint32_t dumped = 0;
                    const unsigned char* sizes_ptr = dir_buf + 4;
                    uint32_t si;
                    printf("\n=== Non-empty streams head dump (max 16 / 32B each) ===\n");
                    for (si = 0; si < num_streams && dumped < 16; si++) {
                        uint32_t ssz = 0; memcpy(&ssz, sizes_ptr + 4ull*si, 4);
                        if (ssz == 0xFFFFFFFFu || ssz == 0) continue;
                        {
                            uint32_t got = 0; unsigned char* sdat = pdb_rebuild_stream(
                                f, dir_buf, dir_size, num_streams, page_size, page_count, si, &got);
                            if (!sdat || got == 0) { if (sdat) free(sdat); continue; }
                            {
                                size_t dump = got < 32 ? got : 32;
                                size_t k;
                                printf("[Stream %u] size=%u  head=", si, (unsigned)got);
                                for (k = 0; k < dump; k++) printf("%02X ", sdat[k]);
                                printf("\n");
                            }
                            free(sdat);
                            dumped++;
                        }
                    }
                }

                // ---- PDB debug info (GUID/Age): rebuild stream 1 (PDB Info) ----

                if (num_streams > 1) {
                    const unsigned char* sizes_ptr = dir_buf + 4; // num_streamsの直後
                    const unsigned char* pages_ptr = sizes_ptr + 4ull * num_streams; // 各ストリームのページ番号配列群
                    // ストリーム1のページ数を算出
                    uint32_t sz0, sz1; memcpy(&sz0, sizes_ptr + 0, 4); memcpy(&sz1, sizes_ptr + 4, 4);
                    if (sz1 != 0xFFFFFFFFu && sz1 > 0) {
                        uint32_t pages0 = (sz0 == 0xFFFFFFFFu || sz0 == 0) ? 0 : (uint32_t)((sz0 + page_size - 1) / page_size);
                        uint32_t pages1 = (uint32_t)((sz1 + page_size - 1) / page_size);
                        size_t need_dir_bytes = (size_t)4 + (size_t)4 * num_streams; // sizesまで
                        size_t need_pages_bytes = (size_t)pages0 + (size_t)pages1; // DWORD数（ストリーム0 + 1）
                        if (dir_size >= need_dir_bytes + need_pages_bytes * sizeof(uint32_t)) {
                            const uint32_t* page_list0 = (const uint32_t*)(pages_ptr);
                            const uint32_t* page_list1 = page_list0 + pages0;
                            // validate page numbers
                            int ok_pages = 1; uint32_t k;
                            for (k = 0; k < pages1; k++) { if (page_list1[k] >= page_count) { ok_pages = 0; break; } }
                            if (!ok_pages) {
                                printf("[WARN] Stream 1 page index out of range\n");
                            } else {
                                // Rebuild Stream 1 (PDB Info)
                                unsigned char* s1 = (unsigned char*)malloc(sz1);
                                if (!s1) {
                                    printf("Error: memory allocation failed (stream1)\n");
                                } else {
                                    uint32_t copied = 0;
                                    for (k = 0; k < pages1 && copied < sz1; k++) {
                                        long off = (long)page_list1[k] * (long)page_size;
                                        uint32_t chunk = (sz1 - copied) < page_size ? (sz1 - copied) : page_size;
                                        if (fseek(f, off, SEEK_SET) != 0) { printf("Error: failed to seek Stream 1 page\n"); break; }
                                        if (fread(s1 + copied, 1, chunk, f) != chunk) { printf("Error: failed to read Stream 1 page\n"); break; }
                                        copied += chunk;
                                    }
                                    if (copied == sz1) {
                                        // PDB Info header: [version(4)] [signature(4)] [age(4)] [guid(16)]
                                        if (sz1 >= 4 + 4 + 4 + 16) {
                                            uint32_t ver, sig, age; GUID g;
                                            memcpy(&ver, s1 + 0, 4);
                                            memcpy(&sig, s1 + 4, 4);
                                            memcpy(&age, s1 + 8, 4);
                                            memcpy(&g,   s1 + 12, 16);
                                            printf("=== PDB Debug Info (Stream 1) ===\n");
                                            printf("Version=%u  Signature=%u  Age=%u\n", (unsigned)ver, (unsigned)sig, (unsigned)age);
                                            printf("GUID={%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
                                                   (unsigned long)g.Data1, g.Data2, g.Data3,
                                                   g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
                                            // Optionally show trailing ASCII PDB path (best-effort, bounds-safe)
                                            {
                                                size_t scan_start = (size_t)(4 + 4 + 4 + 16);
                                                size_t i;
                                                for (i = sz1; i > scan_start; i--) {
                                                    if (s1[i - 1] == '\0') {
                                                        // extract preceding ASCII printable region
                                                        size_t j = i - 1; size_t begin;
                                                        while (j > scan_start) {
                                                            unsigned char c = s1[j - 1];
                                                            if (c >= 0x20 && c <= 0x7E) j--; else break;
                                                        }
                                                        begin = j;
                                                        if (i > begin + 3) {
                                                            printf("PDB Path: %.*s\n", (int)(i - begin - 1), (const char*)(s1 + begin));
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        } else {
                                            printf("[WARN] Stream 1 size is too small to get GUID/Age (size=%u)\n", (unsigned)sz1);
                                        }
                                    }
                                    free(s1);
                                }
                            }
                        } else {
                            printf("[WARN] Not enough page array entries in directory\n");
                        }
                    } else {
                        printf("[WARN] Stream 1 is invalid or empty; cannot get debug info\n");
                    }
                }

                // ---- DBI (Debug Information) header: rebuild stream 3 and display basic fields ----
                if (num_streams > 3) {
                    // Pre-check size for stream 3 from directory
                    const unsigned char* sizes_ptr = dir_buf + 4; // after num_streams
                    uint32_t sz3 = 0xFFFFFFFFu;
                    memcpy(&sz3, sizes_ptr + 4ull * 3, 4);
                    if (sz3 == 0xFFFFFFFFu) {
                        printf("[WARN] DBI stream (3) is marked invalid in directory\n");
                    } else if (sz3 == 0) {
                        printf("[INFO] DBI stream (3) is empty (size=0); skipping rebuild\n");
                    } else {
                        char h[32]; fmt_size_human((uint64_t)sz3, h, sizeof(h));
                        uint32_t pages3 = (uint32_t)((sz3 + page_size - 1) / page_size);
                        printf("[DBG] DBI stream (3) size=%u bytes (%s), pages=%u\n",
                               (unsigned)sz3, h, (unsigned)pages3);
                        uint32_t got_dbi = 0;
                        unsigned char* dbi = pdb_rebuild_stream(
                            f, dir_buf, dir_size, num_streams, page_size, page_count, 3, &got_dbi);
                        if (dbi && got_dbi > 0) {
                            if (pdb_is_plausible_dbi_header(dbi, got_dbi, num_streams)) {
                                int32_t verSig = 0; uint32_t verHdr=0, age=0; uint16_t gsi=0, psi=0, symrec=0;
                                memcpy(&verSig, dbi + 0, 4);
                                memcpy(&verHdr, dbi + 4, 4);
                                memcpy(&age,    dbi + 8, 4);
                                memcpy(&gsi,    dbi + 12, 2);
                                memcpy(&psi,    dbi + 14, 2);
                                memcpy(&symrec, dbi + 18, 2);
                                printf("=== DBI Header (Stream 3) ===\n");
                                printf("verSig=%d verHdr=%u age=%u\n", (int)verSig, (unsigned)verHdr, (unsigned)age);
                                printf("GSI stream=%u  PSI stream=%u  SymRec stream=%u\n",
                                       (unsigned)gsi, (unsigned)psi, (unsigned)symrec);

                                // Parse common DBI substream sizes (with bounds checks)
                                if (got_dbi >= 60) {
                                    // Offsets based on MS/LLVM DBI layout
                                    int32_t szMod=0, szSecCon=0, szSecMap=0, szFileInfo=0, szTS=0, szDbgHdr=0, szEC=0;
                                    uint16_t flags=0, machine=0;
                                    // sizes block starts at offset 20
                                    memcpy(&szMod,      dbi + 20, 4);
                                    memcpy(&szSecCon,   dbi + 24, 4);
                                    memcpy(&szSecMap,   dbi + 28, 4);
                                    memcpy(&szFileInfo, dbi + 32, 4);
                                    memcpy(&szTS,       dbi + 36, 4); // Type Server Index substream size
                                    // 40: MFCTypeServerIndex or reserved (skip)
                                    memcpy(&szDbgHdr,   dbi + 44, 4);
                                    memcpy(&szEC,       dbi + 48, 4);
                                    memcpy(&flags,      dbi + 52, 2);
                                    memcpy(&machine,    dbi + 54, 2);

                                    uint32_t off = 56; // substreams begin after 56 bytes header
                                    // compute and print offsets, guarding negative sizes
                                    typedef struct { const char* name; int32_t size; uint32_t start; } DbiPart;
                                    DbiPart parts[6];
                                    int pi = 0;
                                    parts[pi].name = "ModInfo"; parts[pi].size = szMod; parts[pi].start = off; pi++;
                                    if (szMod > 0) off += (uint32_t)szMod;
                                    parts[pi].name = "SecContrib"; parts[pi].size = szSecCon; parts[pi].start = off; pi++;
                                    if (szSecCon > 0) off += (uint32_t)szSecCon;
                                    parts[pi].name = "SectionMap"; parts[pi].size = szSecMap; parts[pi].start = off; pi++;
                                    if (szSecMap > 0) off += (uint32_t)szSecMap;
                                    parts[pi].name = "FileInfo"; parts[pi].size = szFileInfo; parts[pi].start = off; pi++;
                                    if (szFileInfo > 0) off += (uint32_t)szFileInfo;
                                    parts[pi].name = "TypeServerIndex"; parts[pi].size = szTS; parts[pi].start = off; pi++;
                                    if (szTS > 0) off += (uint32_t)szTS;
                                    parts[pi].name = "ECInfo"; parts[pi].size = szEC; parts[pi].start = off; pi++;
                                    if (szEC > 0) off += (uint32_t)szEC;

                                    printf("Flags=0x%04X  Machine=0x%04X\n", (unsigned)flags, (unsigned)machine);
                                    printf("--- DBI Substreams (size / offset) ---\n");
                                    for (int i = 0; i < pi; i++) {
                                        const char* n = parts[i].name; int32_t sz = parts[i].size; uint32_t st = parts[i].start;
                                        if (sz < 0) {
                                            printf("  %-16s size=%d (invalid)\n", n, sz);
                                            continue;
                                        }
                                        uint32_t end = st + (uint32_t)sz;
                                        int in_range = (st <= got_dbi && end <= got_dbi);
                                        char h[32]; fmt_size_human((uint64_t)(uint32_t)sz, h, sizeof(h));
                                        printf("  %-16s size=%u bytes (%s)  offset=%u %s\n",
                                               n, (unsigned)(uint32_t)sz, h, (unsigned)st,
                                               in_range ? "" : "[OUT-OF-RANGE]");
                                    }

                                    // Debug header region (if any)
                                    if (szDbgHdr > 0) {
                                        uint32_t dbg_off = off; uint32_t dbg_end = dbg_off + (uint32_t)szDbgHdr;
                                        int ok = (dbg_off <= got_dbi && dbg_end <= got_dbi);
                                        printf("  %-16s size=%u bytes  offset=%u %s\n",
                                               "DbgHeader", (unsigned)(uint32_t)szDbgHdr, (unsigned)dbg_off,
                                               ok ? "" : "[OUT-OF-RANGE]");
                                    }
                                } else {
                                    printf("[WARN] DBI size too small for detailed parsing (got=%u)\n", (unsigned)got_dbi);
                                }
                            } else {
                                printf("[WARN] DBI header not plausible (stream 3)\n");
                            }
                            free(dbi);
                        } else {
                            if (dbi) free(dbi);
                            printf("[WARN] Failed to rebuild DBI stream (3) (sz3=%u)\n", (unsigned)sz3);
                        }
                    }
                } else {
                    printf("[WARN] DBI stream (3) not present\n");
                }

                printf("\n");
            }
            free(dir_buf);
            free(dir_page_numbers);
            fclose(f);
            return 0;
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
            printf("=== .text section byte dump ===\n");
            code = malloc(section.SizeOfRawData);
            if (code == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return;
            }
            fseek(file, section.PointerToRawData, SEEK_SET);
            if (fread(code, 1, section.SizeOfRawData, file) != section.SizeOfRawData) {
                fprintf(stderr, "Failed to read data\n");
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

// ===== COFF/OBJ symbol utilities =====
typedef struct {
    int section_number;    // 1-based section index
    DWORD value;           // offset within section
    char name[256];        // symbol name
} OBJ_SYMBOL_INFO;

typedef struct {
    DWORD offset;          // offset from section start
    DWORD type;            // IMAGE_REL_* type
    DWORD sym_index;       // symbol table index
    char  sym_name[256];   // resolved symbol name
} OBJ_RELOC_INFO;

// Declarations depending on OBJ_* types
static void disassemble_text_section_capstone_with_symbols(FILE* file, DWORD section_offset, WORD number_of_sections, uint64_t image_base, int is_64bit,
    const OBJ_SYMBOL_INFO* syms, size_t sym_count, const OBJ_RELOC_INFO* rels, DWORD rel_count);
static char** build_symbol_name_table(FILE* file, DWORD symtab_ptr, DWORD num_syms, DWORD* out_strtab_pos, DWORD* out_strtab_size);
static void free_symbol_name_table(char** names, DWORD num_syms);
static OBJ_RELOC_INFO* collect_text_relocations(FILE* file, DWORD section_offset, WORD number_of_sections,
    DWORD* out_count, int* out_text_index, uint64_t* out_text_start_va, DWORD* out_text_ptr_raw, DWORD* out_text_size,
    char** sym_names, DWORD num_syms, uint64_t image_base);

static int read_coff_string_table(FILE* file, DWORD strtab_pos, DWORD strtab_size, DWORD offset, char* out, size_t out_sz) {
    long cur;
    size_t i;
    int c;
    if (offset == 0 || offset >= strtab_size) return 0;
    cur = ftell(file);
    if (fseek(file, (long)strtab_pos + (long)offset, SEEK_SET) != 0) return 0;
    i = 0;
    while (i + 1 < out_sz && (c = fgetc(file)) != EOF && c != '\0') {
        out[i++] = (char)c;
    }
    out[i] = '\0';
    fseek(file, cur, SEEK_SET);
    return 1;
}

static void print_coff_symbols_and_collect(FILE* file, DWORD symtab_ptr, DWORD num_syms,
                                           OBJ_SYMBOL_INFO** out_syms, size_t* out_count) {
    *out_syms = NULL;
    *out_count = 0;
    if (symtab_ptr == 0 || num_syms == 0) {
        printf("(No symbol table)\n\n");
        return;
    }

    // string table position
    DWORD strtab_pos = symtab_ptr + num_syms * sizeof(IMAGE_SYMBOL);
    DWORD strtab_size = 0;
    long cur = ftell(file);
    if (fseek(file, (long)strtab_pos, SEEK_SET) == 0) {
        fread(&strtab_size, sizeof(DWORD), 1, file);
    }
    fseek(file, cur, SEEK_SET);

    // collect only positive section-number symbols
    size_t cap = 0;
    OBJ_SYMBOL_INFO* buf = NULL;

    printf("=== COFF Symbols ===\n");
    if (fseek(file, (long)symtab_ptr, SEEK_SET) != 0) {
        printf("Cannot seek to symbol table\n\n");
        return;
    }
    {
        DWORD i;
        for (i = 0; i < num_syms; i++) {
        IMAGE_SYMBOL sym;
        char name[256];
        name[0] = '\0';
        if (fread(&sym, sizeof(IMAGE_SYMBOL), 1, file) != 1) break;
        if (sym.N.Name.Short == 0 && sym.N.Name.Long != 0) {
            // long name (from string table)
            DWORD off = sym.N.Name.Long;
            if (!read_coff_string_table(file, strtab_pos + 4, strtab_size - 4, off, name, sizeof(name))) {
                sprintf_s(name, sizeof(name), "<noname@%u>", off);
            }
        } else {
            // short name (<= 8 bytes; may be non-terminated)
            memcpy(name, sym.N.ShortName, 8);
            name[8] = '\0';
        }

        printf("[%5u] Sec=%d Val=0x%08X Type=0x%04X Class=0x%02X Aux=%d Name=%s\n",
               (unsigned)i, (int)sym.SectionNumber, (unsigned)sym.Value, (unsigned)sym.Type,
               (unsigned)sym.StorageClass, (int)sym.NumberOfAuxSymbols, name);

        // collect only positive section-number symbols
        if (sym.SectionNumber > 0) {
            if (*out_count >= cap) {
                cap = cap ? cap * 2 : 64;
                OBJ_SYMBOL_INFO* nb = (OBJ_SYMBOL_INFO*)realloc(buf, cap * sizeof(OBJ_SYMBOL_INFO));
                if (!nb) {
                    free(buf);
                    buf = NULL; *out_count = 0; cap = 0;
                    // give up collection; continue printing only
                } else {
                    buf = nb;
                }
            }
            if (buf) {
                buf[*out_count].section_number = (int)sym.SectionNumber;
                buf[*out_count].value = sym.Value;
                strncpy(buf[*out_count].name, name, sizeof(buf[*out_count].name) - 1);
                buf[*out_count].name[sizeof(buf[*out_count].name) - 1] = '\0';
                (*out_count)++;
            }
        }

        // skip auxiliary symbols
        if (sym.NumberOfAuxSymbols > 0) {
            DWORD skip = (DWORD)sym.NumberOfAuxSymbols;
            if (fseek(file, (long)(skip * sizeof(IMAGE_SYMBOL)), SEEK_CUR) != 0) break;
            i += skip;
        }
        }
    }
    printf("\n");

    *out_syms = buf;
}

static char** build_symbol_name_table(FILE* file, DWORD symtab_ptr, DWORD num_syms,
                                      DWORD* out_strtab_pos, DWORD* out_strtab_size) {
    if (symtab_ptr == 0 || num_syms == 0) return NULL;
    DWORD strtab_pos = symtab_ptr + num_syms * sizeof(IMAGE_SYMBOL);
    DWORD strtab_size = 0;
    long cur = ftell(file);
    if (fseek(file, (long)strtab_pos, SEEK_SET) == 0) fread(&strtab_size, sizeof(DWORD), 1, file);
    fseek(file, cur, SEEK_SET);

    char** names = (char**)calloc(num_syms, sizeof(char*));
    if (!names) return NULL;
    if (fseek(file, (long)symtab_ptr, SEEK_SET) != 0) return names;
    {
        DWORD i;
        for (i = 0; i < num_syms; i++) {
        IMAGE_SYMBOL sym;
        char tmp[256];
        size_t len;
        tmp[0] = '\0';
        if (fread(&sym, sizeof(IMAGE_SYMBOL), 1, file) != 1) break;
        if (sym.N.Name.Short == 0 && sym.N.Name.Long != 0) {
            DWORD off = sym.N.Name.Long;
            if (!read_coff_string_table(file, strtab_pos + 4, strtab_size - 4, off, tmp, sizeof(tmp))) {
                sprintf_s(tmp, sizeof(tmp), "<noname@%u>", off);
            }
        } else {
            memcpy(tmp, sym.N.ShortName, 8); tmp[8] = '\0';
        }
        len = strlen(tmp);
        names[i] = (char*)malloc(len + 1);
        if (names[i]) strcpy_s(names[i], len + 1, tmp);

        // skip auxiliary symbols
        if (sym.NumberOfAuxSymbols > 0) {
            DWORD skip = (DWORD)sym.NumberOfAuxSymbols;
            if (fseek(file, (long)(skip * sizeof(IMAGE_SYMBOL)), SEEK_CUR) != 0) break;
            i += skip;
        }
        }
    }
    if (out_strtab_pos) *out_strtab_pos = strtab_pos;
    if (out_strtab_size) *out_strtab_size = strtab_size;
    return names;
}

static void free_symbol_name_table(char** names, DWORD num_syms) {
    if (!names) return;
    for (DWORD i = 0; i < num_syms; i++) free(names[i]);
    free(names);
}

static OBJ_RELOC_INFO* collect_text_relocations(FILE* file, DWORD section_offset, WORD number_of_sections,
                                                DWORD* out_count, int* out_text_index,
                                                uint64_t* out_text_start_va,
                                                DWORD* out_text_ptr_raw,
                                                DWORD* out_text_size,
                                                char** sym_names, DWORD num_syms, uint64_t image_base) {
    *out_count = 0; if (out_text_index) *out_text_index = -1;
    OBJ_RELOC_INFO* rels = NULL;
    IMAGE_SECTION_HEADER sec;
    {
        int i;
        for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&sec, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (memcmp(sec.Name, ".text", 5) == 0) {
            if (out_text_index) *out_text_index = i;
            if (out_text_start_va) *out_text_start_va = image_base + (uint64_t)sec.VirtualAddress;
            if (out_text_ptr_raw) *out_text_ptr_raw = sec.PointerToRawData;
            if (out_text_size) *out_text_size = sec.SizeOfRawData;
            if (sec.NumberOfRelocations == 0 || sec.PointerToRelocations == 0) return NULL;

            DWORD cnt = sec.NumberOfRelocations;
            rels = (OBJ_RELOC_INFO*)calloc(cnt, sizeof(OBJ_RELOC_INFO));
            if (!rels) return NULL;
            if (fseek(file, sec.PointerToRelocations, SEEK_SET) != 0) { free(rels); return NULL; }
            {
                DWORD r;
                for (r = 0; r < cnt; r++) {
                IMAGE_RELOCATION rel;
                if (fread(&rel, sizeof(IMAGE_RELOCATION), 1, file) != 1) break;
                rels[r].offset = rel.VirtualAddress;
                rels[r].type = rel.Type;
                rels[r].sym_index = rel.SymbolTableIndex;
                if (sym_names && rel.SymbolTableIndex < num_syms && sym_names[rel.SymbolTableIndex]) {
                    strcpy_s(rels[r].sym_name, sizeof(rels[r].sym_name), sym_names[rel.SymbolTableIndex]);
                } else {
                    sprintf_s(rels[r].sym_name, sizeof(rels[r].sym_name), "sym_%u", rel.SymbolTableIndex);
                }
                (*out_count)++;
                }
            }
            break;
        }
        }
    }
    return rels;
}

static void disassemble_text_section_capstone_with_symbols(
    FILE* file, DWORD section_offset, WORD number_of_sections, uint64_t image_base, int is_64bit,
    const OBJ_SYMBOL_INFO* syms, size_t sym_count,
    const OBJ_RELOC_INFO* rels, DWORD rel_count) {
    IMAGE_SECTION_HEADER section;
    int i;
    for (i = 0; i < number_of_sections; i++) {
        fseek(file, section_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (memcmp(section.Name, ".text", 5) == 0) {
            unsigned char* code;
            uint64_t start_va;
            size_t label_count = 0, label_cap = 0;
            uint64_t* label_vas = NULL;
            const char** label_names = NULL;
            csh handle;
            cs_insn* insn = NULL;
            cs_err err;
            cs_mode mode;
            size_t count;

            code = (unsigned char*)malloc(section.SizeOfRawData);
            if (!code) {
                fprintf(stderr, "Memory allocation failed\n");
                return;
            }
            if (fseek(file, section.PointerToRawData, SEEK_SET) != 0 ||
                fread(code, 1, section.SizeOfRawData, file) != section.SizeOfRawData) {
                fprintf(stderr, "Failed to read data\n");
                free(code);
                return;
            }

            printf("=== .text section disassembly (Capstone + Symbols) ===\n");
            /* OBJ: アドレスはセクション先頭からのオフセット基準にする */
            start_va = 0;
            printf("RVA: 0x%08X  Start Off: 0x%016" PRIx64 "  Size: 0x%08X  FileOffset: 0x%08X\n\n",
                   section.VirtualAddress, (uint64_t)start_va, section.SizeOfRawData, section.PointerToRawData);

            // collect only .text symbols and compute their target VAs
            {
                size_t k;
                for (k = 0; k < sym_count; k++) {
                if (syms[k].section_number == (i + 1)) {
                    /* OBJのシンボル値はセクション先頭からのオフセット */
                    uint64_t va = (uint64_t)syms[k].value;
                    if (label_count >= label_cap) {
                        size_t nc = label_cap ? label_cap * 2 : 32;
                        uint64_t* nva = (uint64_t*)realloc(label_vas, nc * sizeof(uint64_t));
                        const char** nnm = (const char**)realloc(label_names, nc * sizeof(const char*));
                        if (!nva || !nnm) { free(nva); free(nnm); break; }
                        label_vas = nva; label_names = nnm; label_cap = nc;
                    }
                    label_vas[label_count] = va;
                    label_names[label_count] = syms[k].name;
                    label_count++;
                }
                }
            }

            mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
            err = cs_open(CS_ARCH_X86, mode, &handle);
            if (err != CS_ERR_OK) {
                fprintf(stderr, "Capstone initialization failed: %d\n", err);
                free(code); free(label_vas); free(label_names);
                return;
            }
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

            count = cs_disasm(handle, code, section.SizeOfRawData, start_va, 0, &insn);
            if (count > 0) {
                size_t j;
                for (j = 0; j < count; j++) {
                    int byte_count;
                    int b;
                    int p;
                    int annotated;
                    // instruction
                    {
                        size_t m;
                        for (m = 0; m < label_count; m++) {
                        if ((uint64_t)insn[j].address == label_vas[m]) {
                            printf("\n; ===== %s =====\n", label_names[m]);
                        }
                        }
                    }
                    // address
                    /* 表示: オフセット + ファイルオフセット併記 */
                    printf("0x%016" PRIx64 " (file+0x%08X): ",
                           (uint64_t)insn[j].address,
                           (unsigned)(section.PointerToRawData + ((uint64_t)insn[j].address - start_va)));
                    // instruction bytes
                    byte_count = (int)insn[j].size;
                    if (byte_count > 10) byte_count = 10;
                    for (b = 0; b < byte_count; b++) printf("%02X ", insn[j].bytes[b]);
                    for (p = byte_count; p < 10; p++) printf("   ");
                    // instruction
                    if (insn[j].op_str && insn[j].op_str[0])
                        printf("  %s %s\n", insn[j].mnemonic, insn[j].op_str);
                    else
                        printf("  %s\n", insn[j].mnemonic);

                    // relocation annotations
                    uint64_t insn_off = (uint64_t)insn[j].address - start_va;
                    annotated = 0;
                    {
                        DWORD rr;
                        for (rr = 0; rr < rel_count; rr++) {
                        uint64_t roff = (uint64_t)rels[rr].offset;
                        if (roff >= insn_off && roff < insn_off + insn[j].size) {
                            if (!annotated) { printf("    ; "); annotated = 1; }
                            printf("rel %s (0x%X) ", rels[rr].sym_name, (unsigned)rels[rr].type);
                        }
                        }
                    }
                    printf("\n");
                }
                cs_free(insn, count);
            } else {
                printf("Disassembly failed\n");
            }
            cs_close(&handle);
            free(code);
            free(label_vas);
            free(label_names);
            break; // .text を処理したら終了
        }
    }
}

// PE 用のシンプルな Capstone 逆アセンブル (.text セクション)
// 先頭アドレスは image_base + section.VirtualAddress
void disassemble_text_section_capstone(
    FILE* file, DWORD section_offset, WORD number_of_sections, uint64_t image_base, int is_64bit) {
    IMAGE_SECTION_HEADER section;
    int i;
    for (i = 0; i < number_of_sections; i++) {
        if (fseek(file, section_offset + i * (long)sizeof(IMAGE_SECTION_HEADER), SEEK_SET) != 0)
            return;
        if (fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1)
            return;
        if (memcmp(section.Name, ".text", 5) == 0) {
            unsigned char* code = NULL;
            uint64_t start_va = image_base + (uint64_t)section.VirtualAddress;
            csh handle;
            cs_insn* insn = NULL;
            cs_mode mode = is_64bit ? CS_MODE_64 : CS_MODE_32;
            size_t count;

            if (section.SizeOfRawData == 0) {
                printf(".text の SizeOfRawData が 0 です\n");
                return;
            }
            code = (unsigned char*)malloc(section.SizeOfRawData);
            if (!code) {
                fprintf(stderr, "メモリ確保に失敗しました\n");
                return;
            }
            if (fseek(file, section.PointerToRawData, SEEK_SET) != 0 ||
                fread(code, 1, section.SizeOfRawData, file) != section.SizeOfRawData) {
                fprintf(stderr, ".text セクションの読み取りに失敗しました\n");
                free(code);
                return;
            }

            printf("=== .text section disassembly (Capstone) ===\n");
            printf("RVA: 0x%08X  Start VA: 0x%016" PRIx64 "  Size: 0x%08X  FileOffset: 0x%08X\n\n",
                   section.VirtualAddress, start_va, section.SizeOfRawData, section.PointerToRawData);

            if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
                fprintf(stderr, "Capstone の初期化に失敗しました\n");
                free(code);
                return;
            }
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

            count = cs_disasm(handle, code, section.SizeOfRawData, start_va, 0, &insn);
            if (count > 0) {
                size_t j;
                for (j = 0; j < count; j++) {
                    int b, byte_count = (int)insn[j].size;
                    if (byte_count > 10) byte_count = 10;
                    printf("0x%016" PRIx64 ": ", (uint64_t)insn[j].address);
                    for (b = 0; b < byte_count; b++) printf("%02X ", insn[j].bytes[b]);
                    for (; b < 10; b++) printf("   ");
                    if (insn[j].op_str && insn[j].op_str[0])
                        printf("  %s %s\n", insn[j].mnemonic, insn[j].op_str);
                    else
                        printf("  %s\n", insn[j].mnemonic);
                }
                cs_free(insn, count);
            } else {
                printf("Disassembly failed\n");
            }
            cs_close(&handle);
            free(code);
            break;
        }
    }
}

int analyze_obj_file(const char* filename) {
    FILE* file;
    IMAGE_FILE_HEADER coff_header;
    DWORD section_offset;
    OBJ_SYMBOL_INFO* syms = NULL; size_t sym_count = 0;
    int is64 = 0;
    DWORD strtab_pos = 0, strtab_size = 0;
    char** sym_names = NULL;
    DWORD rel_count = 0; int text_index = -1; uint64_t text_start_va = 0; DWORD text_ptr_raw = 0; DWORD text_size = 0;
    OBJ_RELOC_INFO* rels = NULL;

    file = fopen(filename, "rb");
    if (!file) {
        printf("エラー: ファイルを開けません '%s'\n", filename);
        return 1;
    }

    // COFF File Header is at the beginning for OBJ files
    if (fread(&coff_header, sizeof(IMAGE_FILE_HEADER), 1, file) != 1) {
        printf("エラー: COFFヘッダの読み取りに失敗しました\n");
        fclose(file);
        return 1;
    }

    // OBJ/COFF 妥当性チェック（PDB/MSF の誤判定や破損ファイルを除外）
    {
        long cur = ftell(file);
        long file_size = 0;
        if (fseek(file, 0, SEEK_END) == 0) {
            file_size = ftell(file);
            fseek(file, cur, SEEK_SET);
        }

        // Machine の既知値チェック
        int machine_ok = 0;
        switch (coff_header.Machine) {
            case IMAGE_FILE_MACHINE_I386:   // 0x14C
            case IMAGE_FILE_MACHINE_AMD64:  // 0x8664
            case IMAGE_FILE_MACHINE_ARM:    // 0x01C0
            case IMAGE_FILE_MACHINE_ARM64:  // 0xAA64
                machine_ok = 1; break;
            default: machine_ok = 0; break;
        }

        // Section 数と OptionalHeader サイズ
        int sect_ok = (coff_header.NumberOfSections >= 1 && coff_header.NumberOfSections <= 96);
        int opt_ok  = (coff_header.SizeOfOptionalHeader == 0); // OBJ は通常 0

        // セクションヘッダ範囲
        section_offset = (DWORD)sizeof(IMAGE_FILE_HEADER) + coff_header.SizeOfOptionalHeader;
        int sect_range_ok = 1;
        if (file_size > 0) {
            long end_of_sects = (long)section_offset + (long)coff_header.NumberOfSections * (long)sizeof(IMAGE_SECTION_HEADER);
            if (end_of_sects < 0 || end_of_sects > file_size) sect_range_ok = 0;
        }

        // シンボル表範囲
        int sym_ok = 1;
        if (coff_header.PointerToSymbolTable != 0 && coff_header.NumberOfSymbols != 0 && file_size > 0) {
            long sym_end = (long)coff_header.PointerToSymbolTable + (long)coff_header.NumberOfSymbols * (long)sizeof(IMAGE_SYMBOL) + 4; // +4 はストリングテーブルサイズ
            if (sym_end < 0 || sym_end > file_size) sym_ok = 0;
        }

        if (!machine_ok || !sect_ok || !opt_ok || !sect_range_ok || !sym_ok) {
            printf("[ERR] このファイルはOBJ/COFFではない可能性があります (PDB/MSF など) 。\n");
            printf("[DBG] Machine=0x%04X, NumberOfSections=%u, SizeOfOptionalHeader=%u, sect_range_ok=%d, sym_ok=%d, file_size=%ld\n",
                   (unsigned)coff_header.Machine, (unsigned)coff_header.NumberOfSections,
                   (unsigned)coff_header.SizeOfOptionalHeader, sect_range_ok, sym_ok, file_size);
            fclose(file);
            return 1;
        }
    }

    printf("=== COFF (OBJ) File Header ===\n");
    print_file_header(&coff_header);

    // Section headers follow immediately after COFF header + SizeOfOptionalHeader
    section_offset = (DWORD)sizeof(IMAGE_FILE_HEADER) + coff_header.SizeOfOptionalHeader;
    /* OBJ用: セクションテーブル範囲と先頭セクションのプローブ検証 */
    {
        long cur_size = 0;
        long cur = ftell(file);
        if (fseek(file, 0, SEEK_END) == 0) { cur_size = ftell(file); }
        fseek(file, cur, SEEK_SET);
        if ((long)section_offset < 0 || (long)section_offset + (long)coff_header.NumberOfSections * (long)sizeof(IMAGE_SECTION_HEADER) > cur_size) {
            printf("[ERR] OBJ: セクションヘッダがファイルサイズを超えています (section_offset=0x%08X, count=%u, file_size=%ld)\n",
                   (unsigned)section_offset, (unsigned)coff_header.NumberOfSections, cur_size);
            fclose(file);
            return 1;
        }
        {
            IMAGE_SECTION_HEADER sec0;
            if (fseek(file, (long)section_offset, SEEK_SET) != 0 || fread(&sec0, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
                printf("[ERR] OBJ: 先頭セクションヘッダーの読み取りに失敗しました\n");
                fclose(file);
                return 1;
            }
            {
                int all_zero = 1; int ni;
                for (ni = 0; ni < 8; ni++) { if (sec0.Name[ni] != 0) { all_zero = 0; break; } }
                if (all_zero) {
                    printf("[WARN] OBJ: 先頭セクション名が全ゼロです（破損の可能性）\n");
                }
            }
            if (sec0.PointerToRawData != 0 && sec0.SizeOfRawData != 0) {
                long end_raw = (long)sec0.PointerToRawData + (long)sec0.SizeOfRawData;
                if (end_raw < 0 || end_raw > cur_size) {
                    printf("[WARN] OBJ: 先頭セクションのRaw範囲がファイル外です (ptr=0x%08X, size=0x%08X, file_size=%ld)\n",
                           (unsigned)sec0.PointerToRawData, (unsigned)sec0.SizeOfRawData, cur_size);
                }
            }
        }
    }
    print_section_headers(file, section_offset, coff_header.NumberOfSections);

    // Dump and collect symbols
    printf("\n");
    printf("PointerToSymbolTable: 0x%08X  NumberOfSymbols: %d\n\n",
           coff_header.PointerToSymbolTable, coff_header.NumberOfSymbols);
    print_coff_symbols_and_collect(file, coff_header.PointerToSymbolTable, coff_header.NumberOfSymbols,
                                   &syms, &sym_count);

    // First pass: count necessary symbols
    // Machine determines 32/64 bit
    switch (coff_header.Machine) {
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM64:
            is64 = 1;
            break;
        default:
            is64 = 0;
            break;
    }

    // build index->name table (used for relocation analysis)
    sym_names = build_symbol_name_table(file, coff_header.PointerToSymbolTable,
                                               coff_header.NumberOfSymbols,
                                               &strtab_pos, &strtab_size);

    // Collect relocations for .text
    rels = collect_text_relocations(file, section_offset, coff_header.NumberOfSections,
                                                    &rel_count, &text_index, &text_start_va,
                                                    &text_ptr_raw, &text_size,
                                                    sym_names, coff_header.NumberOfSymbols, 0);

    // OBJ has no fixed image base; use 0. Disassemble .text with labels and relocation annotations
    disassemble_text_section_capstone_with_symbols(file, section_offset, coff_header.NumberOfSections, 0, is64,
                                                   syms, sym_count,
                                                   rels, rel_count);

    // cleanup
    free(rels);
    free_symbol_name_table(sym_names, coff_header.NumberOfSymbols);
    free(syms);
    fclose(file);
    return 0;
}

void print_section_headers(FILE* file, DWORD section_offset, WORD number_of_sections) {
    printf("=== Section Headers ===\n");
    IMAGE_SECTION_HEADER section;
    char name[9];
    int i;
    /* debug: print section offset and count */
    printf("[DBG] section_offset=0x%08X, number_of_sections=%u, header_size=%u\n",
           (unsigned)section_offset, (unsigned)number_of_sections, (unsigned)sizeof(IMAGE_SECTION_HEADER));
    for (i = 0; i < number_of_sections; i++) {
        if (fseek(file, (long)(section_offset + (DWORD)i * (DWORD)sizeof(IMAGE_SECTION_HEADER)), SEEK_SET) != 0) {
            fprintf(stderr, "[ERR] fseek failed at section %d\n", i);
            break;
        }
        if (fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "[ERR] fread failed at section %d\n", i);
            break;
        }
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
    // Print TimeDateStamp in local time (JST)
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
    printf("ImageBase:                0x%08X\n", (unsigned)opt_header->ImageBase);
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
    printf("SizeOfStackReserve:       0x%08X\n", (unsigned)opt_header->SizeOfStackReserve);
    printf("SizeOfStackCommit:        0x%08X\n", (unsigned)opt_header->SizeOfStackCommit);
    printf("SizeOfHeapReserve:        0x%08X\n", (unsigned)opt_header->SizeOfHeapReserve);
    printf("SizeOfHeapCommit:         0x%08X\n", (unsigned)opt_header->SizeOfHeapCommit);
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
    
    {
        DWORD i;
        for (i = 0; i < count && i < 16; i++) {
        if (data_dirs[i].VirtualAddress != 0 || data_dirs[i].Size != 0) {
            printf("%-25s: RVA=0x%08X Size=0x%08X (%d bytes)\n", 
                   dir_names[i], data_dirs[i].VirtualAddress, 
                   data_dirs[i].Size, data_dirs[i].Size);
        }
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
    printf("ImageBase:                0x%016" PRIx64 "\n", (uint64_t)opt_header->ImageBase);
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
    printf("SizeOfStackReserve:       0x%016" PRIx64 "\n", (uint64_t)opt_header->SizeOfStackReserve);
    printf("SizeOfStackCommit:        0x%016" PRIx64 "\n", (uint64_t)opt_header->SizeOfStackCommit);
    printf("SizeOfHeapReserve:        0x%016" PRIx64 "\n", (uint64_t)opt_header->SizeOfHeapReserve);
    printf("SizeOfHeapCommit:         0x%016" PRIx64 "\n", (uint64_t)opt_header->SizeOfHeapCommit);
    printf("NumberOfRvaAndSizes:      %d\n", opt_header->NumberOfRvaAndSizes);
    printf("\n");
}

int analyze_pe_file(const char* filename) {
    FILE* file;
    IMAGE_DOS_HEADER dos_header;
    DWORD nt_signature;
    IMAGE_FILE_HEADER file_header;
    DWORD section_offset;
    long opt_hdr_pos;
    WORD magic;
    uint64_t image_base_val;
    int is64;
    long file_size;
    
    file = fopen(filename, "rb");
    if (!file) {
        printf("Error: cannot open file '%s'\n", filename);
        return 1;
    }
    
    // Read DOS Header
    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        printf("Error: failed to read DOS Header\n");
        fclose(file);
        return 1;
    }
    {
        long cur;
        if (fseek(file, 0, SEEK_END) != 0) {
            printf("エラー: ファイル末尾へのシークに失敗しました\n");
            fclose(file);
            return 1;
        }
        file_size = ftell(file);
        cur = (long)sizeof(IMAGE_DOS_HEADER);
        if (fseek(file, cur, SEEK_SET) != 0) {
            printf("エラー: DOSヘッダ読込後の位置へ戻れません\n");
            fclose(file);
            return 1;
        }
        printf("[DBG] ファイルサイズ=%ld バイト\n", file_size);
    }
    
    // Check MZ signature
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("エラー: 有効なPEファイルではありません（MZシグネチャが見つかりません）\n");
        fclose(file);
        return 1;
    }
    
    print_dos_header(&dos_header);
    
    // Validate/seek to PE Header
    if ((long)dos_header.e_lfanew < 0 || (long)dos_header.e_lfanew > file_size - (long)sizeof(DWORD)) {
        DWORD old_lfanew = (DWORD)dos_header.e_lfanew;
        long start = (old_lfanew > 0x400) ? ((long)old_lfanew - 0x400) : 0;
        long end = (old_lfanew + 0x400 < (DWORD)file_size) ? ((long)old_lfanew + 0x400) : (file_size - 4);
        long pos;
        int found = 0;
        for (pos = start; pos <= end; pos++) {
            DWORD sig;
            if (fseek(file, pos, SEEK_SET) != 0) break;
            if (fread(&sig, sizeof(DWORD), 1, file) != 1) break;
            if (sig == IMAGE_NT_SIGNATURE) { found = 1; break; }
        }
        if (found) {
            printf("[WARN] PE\\0\\0 の走査により e_lfanew を 0x%08X から 0x%08lX に補正しました\n", (unsigned)old_lfanew, pos);
            dos_header.e_lfanew = (DWORD)pos;
        } else {
            printf("エラー: e_lfanew が範囲外で、想定周辺にPEシグネチャが見つかりません\n");
            fclose(file);
            return 1;
        }
    }
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("エラー: PEヘッダ位置へのシークに失敗しました\n");
        fclose(file);
        return 1;
    }
    
    // Read NT Signature
    if (fread(&nt_signature, sizeof(DWORD), 1, file) != 1) {
        printf("エラー: NTシグネチャの読み取りに失敗しました\n");
        fclose(file);
        return 1;
    }
    {
        unsigned char sig_raw[4];
        memcpy(sig_raw, &nt_signature, 4);
        printf("[DBG] NTシグネチャ(生バイト): %02X %02X %02X %02X\n", sig_raw[0], sig_raw[1], sig_raw[2], sig_raw[3]);
    }
    if (nt_signature != IMAGE_NT_SIGNATURE) {
        printf("エラー: 有効なPEシグネチャが見つかりません\n");
        fclose(file);
        return 1;
    }
    
    // Read FileHeader (manual parse of 20 bytes)
    {
        long fh_pos_expect;
        unsigned char fhdr_raw[20];
        fh_pos_expect = (long)dos_header.e_lfanew + (long)sizeof(DWORD);
        if (fseek(file, fh_pos_expect, SEEK_SET) != 0) {
            printf("エラー: 0x%lX のファイルヘッダ位置へのシークに失敗しました\n", fh_pos_expect);
            fclose(file);
            return 1;
        }
        if (fread(fhdr_raw, 1, 20, file) != 20) {
            printf("エラー: ファイルヘッダの読み取りに失敗しました\n");
            fclose(file);
            return 1;
        }
        printf("[DBG] FILE_HEADER 生バイト: ");
        {
            int di;
            for (di = 0; di < 20; di++) {
                printf("%02X ", fhdr_raw[di] & 0xFF);
            }
            printf("\n");
        }
        // little-endian; memcpy is fine
        memcpy(&file_header.Machine,              fhdr_raw + 0,  2);
        memcpy(&file_header.NumberOfSections,     fhdr_raw + 2,  2);
        memcpy(&file_header.TimeDateStamp,        fhdr_raw + 4,  4);
        memcpy(&file_header.PointerToSymbolTable, fhdr_raw + 8,  4);
        memcpy(&file_header.NumberOfSymbols,      fhdr_raw + 12, 4);
        memcpy(&file_header.SizeOfOptionalHeader, fhdr_raw + 16, 2);
        memcpy(&file_header.Characteristics,      fhdr_raw + 18, 2);
        printf("[DBG] e_lfanew=0x%08X, fh_pos=0x%08lX, NumberOfSections=%u, SizeOfOptionalHeader=%u\n",
               (unsigned)dos_header.e_lfanew, fh_pos_expect, (unsigned)file_header.NumberOfSections, (unsigned)file_header.SizeOfOptionalHeader);
        if (file_header.NumberOfSections == 0 || file_header.NumberOfSections > 96) {
            printf("[ERR] 異常な NumberOfSections=%u\n", (unsigned)file_header.NumberOfSections);
            fclose(file);
            return 1;
        }
        if (file_header.SizeOfOptionalHeader == 0 || file_header.SizeOfOptionalHeader > 4096) {
            printf("[ERR] 異常な SizeOfOptionalHeader=%u\n", (unsigned)file_header.SizeOfOptionalHeader);
            fclose(file);
            return 1;
        }
        {
            IMAGE_NT_HEADERS32 nt_headers_view;
            nt_headers_view.Signature = nt_signature;
            nt_headers_view.FileHeader = file_header;
            print_nt_headers(&nt_headers_view);
            print_file_header(&file_header);
        }
    }
    
    // Determine 32/64 by Optional Header Magic (peek first 2 bytes)
    {
        WORD peek_magic;
        if (fread(&peek_magic, sizeof(WORD), 1, file) != 1) {
            printf("エラー: Optional Header の Magic（先読み）の読み取りに失敗しました\n");
            fclose(file);
            return 1;
        }
        // rewind back to Optional Header start
        if (fseek(file, - (long)sizeof(WORD), SEEK_CUR) != 0) {
            printf("エラー: Optional Header 先頭への戻りシークに失敗しました\n");
            fclose(file);
            return 1;
        }
        if (peek_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            // read and print 64-bit Optional Header
            IMAGE_OPTIONAL_HEADER64 opt64_early;
            if (fread(&opt64_early, sizeof(IMAGE_OPTIONAL_HEADER64), 1, file) != 1) {
                printf("エラー: Optional Header 64 の読み取りに失敗しました\n");
                fclose(file);
                return 1;
            }
            print_optional_header64(&opt64_early);
            print_data_directories(opt64_early.DataDirectory, opt64_early.NumberOfRvaAndSizes);
        } else {
            IMAGE_OPTIONAL_HEADER32 opt32;
            if (fread(&opt32, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file) != 1) {
                printf("エラー: Optional Header 32 の読み取りに失敗しました\n");
                fclose(file);
                return 1;
            }
            print_optional_header(&opt32);
            print_data_directories(opt32.DataDirectory, opt32.NumberOfRvaAndSizes);
        }
    }

    // Print section headers
    section_offset = dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header.SizeOfOptionalHeader;
    printf("[DBG] 計算された section_offset=0x%08X (e_lfanew=0x%08X + 4 + %u + SizeOpt=%u)\n",
           (unsigned)section_offset, (unsigned)dos_header.e_lfanew, (unsigned)sizeof(IMAGE_FILE_HEADER), (unsigned)file_header.SizeOfOptionalHeader);
    if ((long)section_offset < 0 || (long)section_offset + (long)file_header.NumberOfSections * (long)sizeof(IMAGE_SECTION_HEADER) > file_size) {
        printf("[ERR] セクションヘッダがファイルサイズを超えています (section_offset=0x%08X, count=%u, file_size=%ld)\n",
               (unsigned)section_offset, (unsigned)file_header.NumberOfSections, file_size);
        fclose(file);
        return 1;
    }
    /* 追加の信頼性チェック: Optional Header 終端一致と先頭セクションのプローブ */
    {
        long calc_end_of_opt = (long)dos_header.e_lfanew + (long)sizeof(DWORD) + (long)sizeof(IMAGE_FILE_HEADER) + (long)file_header.SizeOfOptionalHeader;
        if (calc_end_of_opt != (long)section_offset) {
            printf("[WARN] section_offset 不一致: calc_end_of_opt=0x%08lX, section_offset=0x%08X\n",
                   calc_end_of_opt, (unsigned)section_offset);
        }
        {
            IMAGE_SECTION_HEADER sec0;
            int ok_probe = 1;
            if (fseek(file, (long)section_offset, SEEK_SET) != 0) {
                printf("[ERR] セクション先頭へのシークに失敗しました (0x%08X)\n", (unsigned)section_offset);
                fclose(file);
                return 1;
            }
            if (fread(&sec0, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
                printf("[ERR] 先頭セクションヘッダーの読み取りに失敗しました\n");
                fclose(file);
                return 1;
            }
            {
                int all_zero = 1; int ni;
                for (ni = 0; ni < 8; ni++) { if (sec0.Name[ni] != 0) { all_zero = 0; break; } }
                if (all_zero) {
                    printf("[WARN] 先頭セクション名が全ゼロです（破損の可能性）\n");
                }
            }
            if (sec0.PointerToRawData != 0 && sec0.SizeOfRawData != 0) {
                long end_raw = (long)sec0.PointerToRawData + (long)sec0.SizeOfRawData;
                if (end_raw < 0 || end_raw > file_size) {
                    printf("[WARN] 先頭セクションのRaw範囲がファイル外です (ptr=0x%08X, size=0x%08X, file_size=%ld)\n",
                           (unsigned)sec0.PointerToRawData, (unsigned)sec0.SizeOfRawData, file_size);
                    ok_probe = 0;
                }
            }
            /* print_section_headers は自身でfseekするため、ここでのファイル位置は影響しない */
            if (!ok_probe) {
                printf("[ERR] セクションヘッダーの妥当性検証に失敗しました\n");
                fclose(file);
                return 1;
            }
        }
    }
    print_section_headers(file, section_offset, file_header.NumberOfSections);

    // Determine ImageBase and bitness by Optional Header Magic
    opt_hdr_pos = (long)dos_header.e_lfanew + (long)sizeof(DWORD) + (long)sizeof(IMAGE_FILE_HEADER);
    if (fseek(file, opt_hdr_pos, SEEK_SET) != 0) {
        printf("エラー: Optional Header へのシークに失敗しました\n");
        fclose(file);
        return 1;
    }
    magic = 0;
    if (fread(&magic, sizeof(WORD), 1, file) != 1) {
        printf("エラー: Optional Header の Magic の読み取りに失敗しました\n");
        fclose(file);
        return 1;
    }
    image_base_val = 0;
    is64 = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // read and print 64-bit Optional Header (to obtain ImageBase)
        if (fseek(file, opt_hdr_pos, SEEK_SET) != 0) {
            printf("エラー: Optional Header 64 へのシークに失敗しました\n");
            fclose(file);
            return 1;
        }
        IMAGE_OPTIONAL_HEADER64 opt64;
        if (fread(&opt64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, file) != 1) {
            printf("エラー: Optional Header 64 の読み取りに失敗しました\n");
            fclose(file);
            return 1;
        }
        image_base_val = (uint64_t)opt64.ImageBase;
        is64 = 1;
    } else {
        // read 32-bit Optional Header (to obtain ImageBase)
        if (fseek(file, opt_hdr_pos, SEEK_SET) != 0) {
            printf("エラー: Optional Header 32 へのシークに失敗しました\n");
            fclose(file);
            return 1;
        }
        IMAGE_OPTIONAL_HEADER32 opt32_ib;
        if (fread(&opt32_ib, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file) != 1) {
            printf("エラー: Optional Header 32 の読み取りに失敗しました\n");
            fclose(file);
            return 1;
        }
        image_base_val = (uint64_t)opt32_ib.ImageBase;
    }

    // Disassemble .text section (Capstone)
    disassemble_text_section_capstone(file, section_offset, (WORD)file_header.NumberOfSections, image_base_val, is64);
    
    fclose(file);
    return 0;
}

/* 簡易使用方法表示 */
static void print_usage(const char* prog) {
    printf("使い方:\n");
    printf("  %s [--auto|--pe|--obj|--pdb] <ファイルパス>\n", prog);
    printf("  %s --help\n", prog);
    printf("\n");
    printf("オプション:\n");
    printf("  --auto  自動判定（デフォルト）。MZならPE、MSFならPDB、その他はOBJを試行\n");
    printf("  --pe    PE解析を実行\n");
    printf("  --obj   OBJ/COFF解析を実行\n");
    printf("  --pdb   PDB/MSF解析を実行\n");
    printf("  --help  このヘルプを表示\n");
    printf("\n例:\n");
    printf("  %s sample.exe\n", prog);
    printf("  %s --pe sample.exe\n", prog);
    printf("  %s --obj sample.obj\n", prog);
    printf("  %s --pdb sample.pdb\n", prog);
}

int main(int argc, char* argv[]) {
    printf("PE/OBJ/PDB 解析ツール\n");
    printf("=====================\n\n");

    /* 引数解析 */
    enum { MODE_AUTO, MODE_PE, MODE_OBJ, MODE_PDB } mode = MODE_AUTO;
    const char* filepath = NULL;

    if (argc <= 1) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "/?") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (argv[1][0] == '-') {
        if (strcmp(argv[1], "--pe") == 0) mode = MODE_PE;
        else if (strcmp(argv[1], "--obj") == 0) mode = MODE_OBJ;
        else if (strcmp(argv[1], "--pdb") == 0) mode = MODE_PDB;
        else if (strcmp(argv[1], "--auto") == 0) mode = MODE_AUTO;
        else {
            printf("[ERR] 不明なオプション: %s\n\n", argv[1]);
            print_usage(argv[0]);
            return 1;
        }
        if (argc < 3) {
            printf("[ERR] ファイルパスを指定してください\n\n");
            print_usage(argv[0]);
            return 1;
        }
        filepath = argv[2];
    } else {
        /* オプションなし: 自動判定で argv[1] を処理 */
        mode = MODE_AUTO;
        filepath = argv[1];
    }

    printf("File: %s\n\n", filepath);

    int result = 1;
    if (mode == MODE_PE) {
        result = analyze_pe_file(filepath);
        if (result == 0) printf("PE Header analysis completed\n");
        return result;
    }
    if (mode == MODE_OBJ) {
        result = analyze_obj_file(filepath);
        if (result == 0) printf("OBJ (COFF) analysis completed\n");
        return result;
    }
    if (mode == MODE_PDB) {
        result = analyze_pdb_file(filepath);
        if (result == 0) printf("PDB (MSF) analysis completed\n");
        return result;
    }

    /* MODE_AUTO: 既存の自動判定ロジックを踏襲 */
    {
        FILE* f = fopen(filepath, "rb");
        if (!f) {
            printf("エラー: ファイルを開けません\n");
            return 1;
        }
        unsigned char buf[64] = {0};
        size_t rd = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (rd >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
            result = analyze_pe_file(filepath);
            if (result == 0) printf("PE Header analysis completed\n");
        } else if (rd >= 18 && buf_contains(buf, rd, "Microsoft C/C++ MSF", 18)) {
            result = analyze_pdb_file(filepath);
            if (result == 0) printf("PDB (MSF) analysis completed\n");
        } else {
            result = analyze_obj_file(filepath);
            if (result == 0) {
                printf("OBJ (COFF) analysis completed\n");
            } else {
                /* 万一OBJ失敗ならPEを再試行（従来踏襲） */
                result = analyze_pe_file(filepath);
            }
        }
    }

    return result;
}