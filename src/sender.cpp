#include "sender.h"
#include "log.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#undef WIN32_LEAN_AND_MEAN

#include "te-sdk.h"
#include "BitStream.h"
#include "PacketPriority.h"
#include "PacketEnumerations.h"

// SW_AC v1.3 protocol (reverse-engineered from SW_AC (1).asi):
//
// Byte order: always little-endian (big-endian flag never triggered).
// Transport:  MEDIUM_PRIORITY(2) / RELIABLE_ORDERED(9) / channel 0
//
//  0xF0 — Registration:       [LE16:0x00F0][LE32:hwid_token][LE32:version=0x01030000]
//  0xF2 — AC message:         [LE16:0x00F2][LE16:strlen+1][msg+NUL]
//  0xF4 — Challenge response: [LE16:0x00F4][LE32:SWAC_magic][LE32:response][LE32:version][LE32:uptime]
//  0xF5 — Heartbeat:          [LE16:0x00F5][LE32:session_id][1 byte:player_state]
//
//  0xF3 — Incoming challenge (server→client):
//           direct:       [0xF3][0x00][SWAC_LE32][challenge_LE32]
//           0x28-wrapped: [0x28][4 bytes][0xF3][0x00][SWAC_LE32][challenge_LE32]
//
// Hash constants (XOR-decrypted from .data at init — all fixed, not device-specific):
//   G288 = 0x53574143  (SWAC magic — also used as session token in 0xF4)
//   G12C = 0xA3B2C1D0
//   G2CC = 0x0FEDCBA9
//   G284 = 0x13579BDF
//   G388 = 0xABCD1234
//   G134 = 0x0F1E2D3C
//   G398 = 0xDEADBEEF
//   G128 = SessionSalt (fetched via HTTPS from SW server — unavailable, use 0)

namespace {

constexpr size_t   MAX_MSG_LEN  = 512;
constexpr uint32_t SWAC_MAGIC   = 0x53574143u;  // "SWAC"
constexpr uint32_t SWAC_VERSION = 0x01030000u;  // v1.3

// HWID token sent in 0xF0 — server logs/bans by it; use SWAC magic as placeholder
constexpr uint32_t HWID_TOKEN   = 0x53574143u;

// v1.3 hash constants (disassembled from 0x10066300-0x10066393)
constexpr uint32_t G12C = 0xA3B2C1D0u;
constexpr uint32_t G2CC = 0x0FEDCBA9u;
constexpr uint32_t G284 = 0x13579BDFu;
constexpr uint32_t G388 = 0xABCD1234u;
constexpr uint32_t G134 = 0x0F1E2D3Cu;
constexpr uint32_t G398 = 0xDEADBEEFu;

// SessionSalt — fetched via HTTPS from /anticheat/session-salt?server=IP:PORT
std::atomic<uint32_t> g_G128{0u};

DWORD             g_connectTime{0};
std::atomic<bool> g_sentOnThisConnect{false};
std::atomic<bool> g_connected{false};
std::atomic<bool> g_challengeReceived{false};  // set when 0xF3 arrives — heartbeat window closed

inline void WriteLE16(RakNet::BitStream& bs, uint16_t v)
{
    bs.Write(uint8_t(v & 0xFF));
    bs.Write(uint8_t(v >> 8));
}
inline void WriteLE32(RakNet::BitStream& bs, uint32_t v)
{
    bs.Write(uint8_t(v & 0xFF));
    bs.Write(uint8_t((v >> 8)  & 0xFF));
    bs.Write(uint8_t((v >> 16) & 0xFF));
    bs.Write(uint8_t(v >> 24));
}

// ── Session salt HTTPS fetch ──────────────────────────────────────────────────
// Parse "[N]" from SA-MP server display name (e.g. "(SW:AC) Secret Weapon [1] ...")
static int ParseSwacServerNum(const char* name)
{
    if (!name) return 1;
    for (const char* p = name; *p; ++p) {
        if (*p == '[' && p[1] >= '1' && p[1] <= '9' && p[2] == ']')
            return p[1] - '0';
    }
    return 1;
}

// Synchronous HTTPS GET → returns 0 on failure or the parsed session salt
static uint32_t DoFetchSalt(int server_num, const char* server_addr)
{
    wchar_t whost[64];
    swprintf_s(whost, L"swac-%d.swdm.my.id", server_num);

    wchar_t wpath[128];
    swprintf_s(wpath, L"/anticheat/session-salt?server=%hs", server_addr);

    HINTERNET hSes = WinHttpOpen(L"SW-Anticheat/1.0.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return 0;

    HINTERNET hCon = WinHttpConnect(hSes, whost, 443, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return 0; }

    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", wpath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return 0; }

    // Same security flags as real plugin (ignore cert date/unknown CA)
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    WinHttpAddRequestHeaders(hReq, L"Accept: application/json\r\n",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    uint32_t salt = 0;
    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hReq, NULL))
    {
        DWORD status = 0, szStatus = sizeof(status);
        WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &szStatus,
            WINHTTP_NO_HEADER_INDEX);

        // Read body (response is small: {"session_salt":"XXXXXXXX"})
        char body[512] = {};
        DWORD avail = 0, read = 0, bodyLen = 0;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0
               && bodyLen < sizeof(body) - 1)
        {
            DWORD toRead = avail < (DWORD)(sizeof(body) - 1 - bodyLen)
                         ? avail : (DWORD)(sizeof(body) - 1 - bodyLen);
            WinHttpReadData(hReq, body + bodyLen, toRead, &read);
            bodyLen += read;
        }

        Log("[sw_ac_emu] FetchSalt N=%d status=%lu body=%s", server_num, status, body);

        if (status == 200) {
            const char* key = "\"session_salt\":\"";
            const char* pos = strstr(body, key);
            if (pos) {
                salt = strtoul(pos + strlen(key), nullptr, 16);
                Log("[sw_ac_emu] G128 = 0x%08X (from swac-%d)", salt, server_num);
            }
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hCon);
    WinHttpCloseHandle(hSes);
    return salt;
}

// Called in a detached thread at connection time
static void FetchSessionSalt()
{
    // Get server IP:PORT from te::sdk session info (safe, no vtable crash)
    const te::sdk::SessionInfo& si = te::sdk::GetSessionInfo();
    if (si.serverIP[0] == '\0' || si.serverPort == 0) {
        Log("[sw_ac_emu] FetchSalt: no session info (ip='%s' port=%u)",
            si.serverIP, (unsigned)si.serverPort);
        return;
    }

    char server_addr[80];
    snprintf(server_addr, sizeof(server_addr), "%s:%u", si.serverIP, (unsigned)si.serverPort);

    // Wait up to 5s for SA-MP server display name to contain "[N]"
    int server_num = 1;
    for (int i = 0; i < 25; ++i) {
        const char* name = te::sdk::helper::samp::GetServerName();
        if (name && strstr(name, "[")) {
            server_num = ParseSwacServerNum(name);
            Log("[sw_ac_emu] FetchSalt: server='%s' N=%d addr=%s",
                name, server_num, server_addr);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    Log("[sw_ac_emu] FetchSalt: addr=%s N=%d (fetching)", server_addr, server_num);

    // Try the parsed N first, then fall back to N=1..5
    uint32_t salt = DoFetchSalt(server_num, server_addr);
    for (int n = 1; n <= 5 && !salt; ++n) {
        if (n == server_num) continue;
        salt = DoFetchSalt(n, server_addr);
    }

    if (salt)
        g_G128.store(salt);
    else
        Log("[sw_ac_emu] FetchSalt: all attempts failed — G128=0");
}

// ── Registration ─────────────────────────────────────────────────────────────
bool SendRegistration()
{
    if (!te::sdk::LocalClient)
    {
        Log("[sw_ac_emu] SendRegistration: LocalClient not ready");
        return false;
    }
    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F0);
    WriteLE32(bs, HWID_TOKEN);
    WriteLE32(bs, SWAC_VERSION);
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    Log("[sw_ac_emu] 0xF0 Registration(hwid=0x%08X ver=0x%08X) -> %s",
        HWID_TOKEN, SWAC_VERSION, ok ? "ok" : "FAIL");
    return ok;
}

// ── 0xF2 AC message ───────────────────────────────────────────────────────────
bool SendACMessage(const char* message)
{
    if (!te::sdk::LocalClient)
    {
        Log("[sw_ac_emu] SendACMessage: LocalClient not ready");
        return false;
    }
    if (!message || !*message) return false;
    const size_t len = std::strlen(message);
    if (len > MAX_MSG_LEN) return false;

    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F2);
    WriteLE16(bs, static_cast<uint16_t>(len + 1));
    bs.Write(message, static_cast<int>(len + 1));
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    Log("[sw_ac_emu] 0xF2 ACMessage('%s') -> %s", message, ok ? "ok" : "FAIL");
    return ok;
}

// ── v1.3 Challenge-response hash ──────────────────────────────────────────────
// Disassembled from SW_AC (1).asi @ 0x10066310-0x10066393.
uint32_t compute_response(uint32_t c)
{
    const uint32_t salt = g_G128.load();
    uint32_t ecx = salt;                             // SessionSalt
    uint32_t esi = SWAC_MAGIC;                       // G288
    uint32_t eax = G12C ^ ecx ^ esi ^ c;
    eax += G2CC;

    ecx = c ^ 0x40c000u;
    ecx = (ecx << 5) + eax;

    uint32_t edi = (esi << 4) + esi;                 // G288 * 17 = 0x88CB5573
    uint32_t edx = ecx;

    eax  = (c << 11) ^ G388;
    edx  = (edx << 7) + G284;
    edx ^= ecx;
    edx += eax;

    ecx  = c ^ 0x01030000u;
    edx += (ecx << 5) + ecx;                         // += ecx * 33

    edi ^= (edx << 13);
    edi ^= edx;
    edi += G134 ^ salt ^ 0x04030000u;

    if (edi == 0)
        edi = G398 ^ c;
    return edi;
}

// ── 0xF4 Challenge response ───────────────────────────────────────────────────
bool SendChallengeResponse(uint32_t challenge)
{
    if (!te::sdk::LocalClient)
    {
        Log("[sw_ac_emu] SendChallengeResponse: LocalClient not ready");
        return false;
    }
    const uint32_t response = compute_response(challenge);
    const uint32_t uptime   = g_connectTime ? (GetTickCount() - g_connectTime) : GetTickCount();

    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F4);
    WriteLE32(bs, SWAC_MAGIC);
    WriteLE32(bs, response);
    WriteLE32(bs, SWAC_VERSION);
    WriteLE32(bs, uptime);
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    Log("[sw_ac_emu] 0xF4 ChallengeResponse(ch=0x%08X resp=0x%08X uptime=%u) -> %s",
        challenge, response, uptime, ok ? "ok" : "FAIL");
    return ok;
}

// ── 0xF5 Heartbeat ────────────────────────────────────────────────────────────
// Sent periodically to signal player state (pause_menu | out_of_window<<1).
// [0x1020d008] = 0x53574143 (SWAC magic) — XOR-decrypted from binary.
bool SendHeartbeat(uint8_t player_state = 0)
{
    if (!te::sdk::LocalClient) return false;

    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F5);
    WriteLE32(bs, SWAC_MAGIC);   // session_id = [0x1020d008] = 0x53574143
    bs.Write(player_state);      // bit0=pause_menu, bit1=out_of_window
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    const DWORD t = g_connectTime ? (GetTickCount() - g_connectTime) : 0;
    Log("[sw_ac_emu] 0xF5 Heartbeat(state=%u T+%ums) -> %s", player_state, t, ok ? "ok" : "FAIL");
    return ok;
}

// ── Parse raw 0xF3 challenge ──────────────────────────────────────────────────
bool TryParseChallenge(const uint8_t* raw, int len, uint32_t& challenge_out)
{
    // Log raw bytes for protocol analysis
    {
        char hex[256] = {};
        int n = 0;
        for (int i = 0; i < len && i < 20; ++i)
            n += snprintf(hex + n, sizeof(hex) - n, "%02X ", raw[i]);
        Log("[sw_ac_emu] 0xF3/0x28 raw(%d): %s", len, hex);
    }

    auto readLE32 = [&](int off) -> uint32_t {
        return uint32_t(raw[off])
             | uint32_t(raw[off + 1]) <<  8
             | uint32_t(raw[off + 2]) << 16
             | uint32_t(raw[off + 3]) << 24;
    };

    // Format A: [0xF3][LE32:SWAC_magic][LE32:challenge]  (9 bytes, no padding byte)
    if (len >= 9 && raw[0] == 0xF3)
    {
        uint32_t magic = readLE32(1);
        if (magic == SWAC_MAGIC) {
            challenge_out = readLE32(5);
            Log("[sw_ac_emu] 0xF3 fmt-A magic=0x%08X ch=0x%08X", magic, challenge_out);
            return true;
        }
    }
    // Format B: [0xF3][0x00][LE32:SWAC_magic][LE32:challenge]  (10 bytes, extra 0x00)
    if (len >= 10 && raw[0] == 0xF3 && raw[1] == 0x00)
    {
        uint32_t magic = readLE32(2);
        if (magic == SWAC_MAGIC) {
            challenge_out = readLE32(6);
            Log("[sw_ac_emu] 0xF3 fmt-B magic=0x%08X ch=0x%08X", magic, challenge_out);
            return true;
        }
    }
    // Format C: outer packet 0x28, inner 0xF3 at offset 5
    // [0x28][4 bytes][0xF3][0x00][LE32:SWAC_magic][LE32:challenge]
    if (len >= 15 && raw[0] == 0x28 && raw[5] == 0xF3 && raw[6] == 0x00)
    {
        uint32_t magic = readLE32(7);
        if (magic == SWAC_MAGIC) {
            challenge_out = readLE32(11);
            Log("[sw_ac_emu] 0xF3 fmt-C magic=0x%08X ch=0x%08X", magic, challenge_out);
            return true;
        }
    }

    Log("[sw_ac_emu] TryParseChallenge: NO match (len=%d raw[0]=0x%02X raw[1]=0x%02X)",
        len, raw[0], len > 1 ? raw[1] : 0);
    return false;
}

// ── Continuous heartbeat loop ─────────────────────────────────────────────────
// Real SW_AC monitoring loop (0x10064B00) runs at 100ms, sends on first
// post-spawn iteration and on every state change.
//
// We mimic this with a continuous 200ms loop starting at T+2 (connect+2s).
// State alternates every ~30s (inactive=0 ↔ focus=0) to produce realistic
// traffic; we never alt-tab so bit1 stays 0 permanently.
void HeartbeatStateLoop()
{
    // Wait until T+2 before first send (registration/0xF2 need to arrive first)
    {
        DWORD elapsed = GetTickCount() - g_connectTime;
        int wait = 2000 - (int)elapsed;
        if (wait > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(wait));
    }

    // Continuous 200ms heartbeat — guarantees a fresh packet when server checks.
    // Server timer fires ~T+8–T+10; any 0xF5 within last 2s satisfies it.
    constexpr int INTERVAL_MS = 200;
    while (g_connected.load())
    {
        SendHeartbeat(0);
        std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL_MS));
    }
}

// ── Incoming packet handler ───────────────────────────────────────────────────
bool OnIncomingPacket(const te::sdk::PacketContext& ctx)
{
    if (ctx.packetId == uint32_t(ID_CONNECTION_REQUEST_ACCEPTED))
    {
        if (g_sentOnThisConnect.exchange(true))
            return true;
        g_connectTime = GetTickCount();
        g_connected.store(true);
        Log("[sw_ac_emu] Connected — sending SW:AC v1.3 registration");

        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            SendRegistration();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            SendACMessage("hello");
        }).detach();

        std::thread(FetchSessionSalt).detach();
        std::thread(HeartbeatStateLoop).detach();
        return true;
    }

    if (ctx.packetId == uint32_t(ID_DISCONNECTION_NOTIFICATION) ||
        ctx.packetId == uint32_t(ID_CONNECTION_LOST))
    {
        g_connected.store(false);
        g_sentOnThisConnect.store(false);
        g_challengeReceived.store(false);
        g_connectTime = 0;
        Log("[sw_ac_emu] Disconnected");
        return true;
    }

    // Incoming 0xF3 challenge (direct or SA-MP 0x28-wrapped)
    if (ctx.packetId == 0xF3 || ctx.packetId == 0x28)
    {
        auto* bs           = static_cast<RakNet::BitStream*>(ctx.bitStream);
        const uint8_t* raw = bs->GetData();
        const int      rlen = bs->GetNumberOfBytesUsed();

        uint32_t challenge = 0;
        if (TryParseChallenge(raw, rlen, challenge))
        {
            g_challengeReceived.store(true);
            // Send 0xF5 immediately BEFORE 0xF4 and then again right after.
            // The continuous loop also runs at 200ms, but this guarantees a
            // heartbeat reaches the server in the same RTT window as 0xF4.
            SendHeartbeat(0);
            SendChallengeResponse(challenge);  // 0xF4
            SendHeartbeat(0);
        }
    }

    return true;
}

} // namespace

void InstallHooks()
{
    te::sdk::RegisterRaknetCallback(HookType::IncomingPacket, OnIncomingPacket);

    te::sdk::helper::samp::RegisterChatCommand("acmsg", [](const char* params) {
        if (!params || !*params)
        {
            te::sdk::helper::samp::AddChatMessage(
                "[sw_ac_emu] Usage: /acmsg <message>", 0xFFFFAA00u);
            return;
        }
        std::string msg(params);
        const size_t start = msg.find_first_not_of(" \t");
        if (start == std::string::npos) return;
        if (start > 0) msg.erase(0, start);
        SendACMessage(msg.c_str());
    });

    Log("[sw_ac_emu] Hooks installed (SW:AC v1.3 — 0xF0/F2/F4/F5)");
}
