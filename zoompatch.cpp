// zoompatch.cpp - find the camera zoom-clamp "jbe short" in elementclient exe and flip it to "jmp short".
//
// Build (w64devkit), with the embedded manifest (see zoompatch.manifest / zoompatch.rc):
//   windres zoompatch.rc -O coff -o zoompatch_res.o
//   g++ -O2 -std=c++17 -static -o zoompatch.exe zoompatch.cpp zoompatch_res.o
//
// UAC: the manifest says "asInvoker", so Windows never auto-elevates this exe (without it, the
// name "...patch..." triggers installer detection and the usage text vanishes into a new window).
// Dry runs never need admin. If --apply/--revert can't write (e.g. game in Program Files), the
// tool relaunches itself elevated at that point, waits for it, and returns its exit code.
//
// Usage:
//   zoompatch.exe <exe>            dry run: report what would change
//   zoompatch.exe <exe> --apply    make <exe>.bak (once) and patch in place
//   zoompatch.exe <exe> --revert   flip the patched site back to JBE (0x76)
//
// No disassembler needed: the code is matched structurally on raw bytes, tolerant of register choice.
//
// Shape matched (x64 shown; x86 uses offsets 0x40/0x6C/0x68 and no REX):
//   movss xmm,[reg+0x44]  / movss xmm,[reg+0x70] / movss xmm,[reg+0x6C]   (loads within a short window)
//   comiss ...                                                            (0F 2F)
//   movss [reg+0x44],xmm                                                  (F3 [REX] 0F 11 modrm 44)
//   jbe short (76 rel8)    <-- patch site, 0x76 -> 0xEB
// Exactly one candidate must match, otherwise nothing is touched.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

using Bytes = std::vector<uint8_t>;

#ifdef _WIN32
// Re-run this exe elevated ("runas") with the same arguments plus --elevated, wait for it, and
// pass back its exit code. Returns false if the user declined UAC or the launch failed.
static bool relaunchElevated(int argc, char** argv, int& exitCode) {
    std::string params;
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--elevated")) continue;
        params += "\"" + std::string(argv[i]) + "\" ";
    }
    params += "--elevated";
    char exe[MAX_PATH], cwd[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, exe, MAX_PATH) || !GetCurrentDirectoryA(MAX_PATH, cwd)) return false;
    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = exe;
    sei.lpParameters = params.c_str();
    sei.lpDirectory = cwd; // so a relative <exe> path still resolves in the elevated copy
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExA(&sei) || !sei.hProcess) return false;
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    exitCode = (int)code;
    return true;
}
#endif

static uint16_t rd16(const Bytes& b, size_t o) { return b[o] | (b[o + 1] << 8); }
static uint32_t rd32(const Bytes& b, size_t o) { return rd16(b, o) | ((uint32_t)rd16(b, o + 2) << 16); }
static uint64_t rd64(const Bytes& b, size_t o) { return rd32(b, o) | ((uint64_t)rd32(b, o + 4) << 32); }

struct Section { uint32_t va, rawOff, rawSize, vsize, flags; };

// Is there "movss xmm,[reg+disp8]" (F3 [REX] 0F 10 modrm disp8, mod=01, no SIB) with disp8 == disp,
// whose bytes lie entirely in [lo, hi)?
static bool hasLoad(const Bytes& d, size_t lo, size_t hi, uint8_t disp, bool x64) {
    for (size_t i = lo; i + 5 <= hi; i++) {
        if (d[i] != 0xF3) continue;
        size_t p = i + 1;
        if (x64 && (d[p] & 0xF0) == 0x40) p++;
        if (p + 4 > hi) continue;
        if (d[p] != 0x0F || d[p + 1] != 0x10) continue;
        uint8_t modrm = d[p + 2];
        if ((modrm & 0xC0) != 0x40 || (modrm & 7) == 4) continue; // mod=01, not SIB
        if (d[p + 3] == disp) return true;
    }
    return false;
}

struct Hit { size_t fileOff; uint64_t va; uint8_t cur; };

static int run(int argc, char** argv, bool elevated) {
    if (argc < 2) { std::puts("usage: zoompatch <exe> [--apply|--revert]"); return 2; }
    std::string path = argv[1];
    bool apply = false, revert = false;
    for (int i = 2; i < argc; i++) {
        if (!std::strcmp(argv[i], "--apply")) apply = true;
        else if (!std::strcmp(argv[i], "--revert")) revert = true;
    }
    (void)elevated;

    std::ifstream in(path, std::ios::binary);
    if (!in) { std::printf("cannot open %s\n", path.c_str()); return 1; }
    Bytes d((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (d.size() < 0x400 || d[0] != 'M' || d[1] != 'Z') { std::puts("not a PE file"); return 1; }
    uint32_t pe = rd32(d, 0x3C);
    if (pe + 24 > d.size() || std::memcmp(&d[pe], "PE\0\0", 4) != 0) { std::puts("bad PE header"); return 1; }
    uint16_t machine = rd16(d, pe + 4), nsec = rd16(d, pe + 6), optSize = rd16(d, pe + 20);
    size_t opt = pe + 24;
    bool x64 = machine == 0x8664;
    if (!x64 && machine != 0x14C) { std::puts("unsupported machine type"); return 1; }
    uint64_t imageBase = x64 ? rd64(d, opt + 24) : rd32(d, opt + 28);

    std::vector<Section> secs;
    size_t sh = opt + optSize;
    for (int i = 0; i < nsec; i++, sh += 40) {
        Section s{rd32(d, sh + 12), rd32(d, sh + 20), rd32(d, sh + 16), rd32(d, sh + 8), rd32(d, sh + 36)};
        if (s.flags & 0x20) secs.push_back(s); // IMAGE_SCN_CNT_CODE
    }

    // field offsets inside the camera object
    uint8_t cur = x64 ? 0x44 : 0x40, minB = x64 ? 0x70 : 0x6C, maxB = x64 ? 0x6C : 0x68;
    const size_t LOOKBACK = 64;

    std::vector<Hit> hits;
    for (const auto& s : secs) {
        size_t beg = s.rawOff, end = std::min<size_t>(s.rawOff + s.rawSize, d.size());
        for (size_t i = beg + LOOKBACK; i + 8 <= end; i++) {
            // store: F3 [REX] 0F 11 modrm disp8==cur, then jbe short (0x76) or already-patched (0xEB)
            if (d[i] != 0xF3) continue;
            size_t p = i + 1;
            if (x64 && (d[p] & 0xF0) == 0x40) p++;
            if (d[p] != 0x0F || d[p + 1] != 0x11) continue;
            uint8_t modrm = d[p + 2];
            if ((modrm & 0xC0) != 0x40 || (modrm & 7) == 4 || d[p + 3] != cur) continue;
            size_t j = p + 4; // byte after the store = the jbe opcode
            if (j + 2 > end) continue;
            if (d[j] != 0x76 && d[j] != 0xEB) continue;

            // a comiss (0F 2F) must sit shortly before the store
            bool comiss = false;
            for (size_t k = i >= 8 ? i - 8 : 0; k + 1 < i; k++)
                if (d[k] == 0x0F && d[k + 1] == 0x2F) { comiss = true; break; }
            if (!comiss) continue;

            // both bounds and the current-distance field must be loaded just before
            size_t lo = i - LOOKBACK;
            if (!hasLoad(d, lo, i, cur, x64) || !hasLoad(d, lo, i, minB, x64) || !hasLoad(d, lo, i, maxB, x64)) continue;

            hits.push_back({j, imageBase + s.va + (j - s.rawOff), d[j]});
        }
    }

    std::printf("%s, %zu candidate(s)\n", x64 ? "x64" : "x86", hits.size());
    for (auto& h : hits)
        std::printf("  VA 0x%llX  file offset 0x%zX  byte %02X (%s)\n", (unsigned long long)h.va, h.fileOff, h.cur,
                    h.cur == 0x76 ? "JBE - original" : "JMP - already patched");
    if (hits.size() != 1) { std::puts(hits.empty() ? "no match - nothing changed" : "ambiguous - nothing changed"); return 1; }

    const Hit& h = hits[0];
    uint8_t want = revert ? 0x76 : 0xEB;
    if (!apply && !revert) { std::printf("dry run: would change %02X -> %02X (use --apply)\n", h.cur, want); return 0; }
    if (h.cur == want) { std::puts("already in the requested state"); return 0; }

    // Anything that fails here with "denied" (read-only dir/file) is the cue to elevate - before
    // anything has been modified.
    auto needElevation = [&](const char* why) -> int {
#ifdef _WIN32
        if (!elevated) {
            std::printf("%s - requesting administrator rights...\n", why);
            int code = 1;
            if (relaunchElevated(argc, argv, code)) return code;
            std::puts("elevation was declined or failed - nothing changed");
            return 1;
        }
#endif
        std::printf("%s\n", why);
        return 1;
    };

    if (!revert) {
        std::ifstream chk(path + ".bak", std::ios::binary);
        if (!chk) {
            std::ofstream bak(path + ".bak", std::ios::binary);
            bak.write((const char*)d.data(), d.size());
            bak.flush();
            if (!bak) return needElevation("cannot create backup next to the exe");
            std::puts("backup written: .bak");
        }
    }
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f) return needElevation("cannot open the exe for writing (is the game running? is it in a protected folder?)");
    f.seekp((std::streamoff)h.fileOff);
    f.put((char)want);
    f.flush();
    if (!f) { std::puts("write failed"); return 1; }
    std::printf("patched: %02X -> %02X at file offset 0x%zX\n", h.cur, want, h.fileOff);
    return 0;
}

int main(int argc, char** argv) {
    bool elevated = false;
    for (int i = 1; i < argc; i++)
        if (!std::strcmp(argv[i], "--elevated")) elevated = true;
    int rc = run(argc, argv, elevated);
    if (elevated) { // the elevated copy has its own console window that would vanish instantly
        std::puts("\nPress Enter to close...");
        std::getchar();
    }
    return rc;
}
