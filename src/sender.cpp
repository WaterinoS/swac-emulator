#include "sender.h"
#include "log.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include "te-sdk.h"
#include "BitStream.h"
#include "PacketPriority.h"
#include "PacketEnumerations.h"

// SW_AC.asi byte-order notes:
// The flag at [0x101f5600] (set only when GetTickCount()==12345) is effectively
// always 0, so the BitStream Write path that byte-swaps to big-endian is never
// reached. All outgoing SWAC packets are therefore little-endian (LE).
//
// Packet map (all multi-byte fields LE, transport MEDIUM_PRIORITY/RELIABLE_ORDERED/ch0):
//
//  0xF0 — Registration (10 B): [type_LE16][SWAC_LE32][version_LE32]
//  0xF2 — AC message:          [type_LE16][strlen+1_LE16][msg+NUL]
//  0xF4 — Challenge response:  [type_LE16][SWAC_LE32][response_LE32][version_LE32][uptime_LE32]
//
//  0xF3 — Incoming challenge (server→client):
//           direct:      [0xF3][0x00][SWAC_LE32][challenge_LE32]
//           0x28-wrapped: [0x28][4 bytes][0xF3][0x00][SWAC_LE32][challenge_LE32]

namespace {

constexpr size_t   MAX_MSG_LEN  = 512;
constexpr uint32_t SWAC_MAGIC   = 0x53574143u; // "SWAC" as LE uint32 = 0x43 0x41 0x57 0x53
constexpr uint32_t SWAC_VERSION = 0x01020000u;

DWORD                g_connectTime{0};
std::atomic<bool>    g_sentOnThisConnect{false};

// Write an integer as little-endian bytes.
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

// ── 0xF0 Registration ─────────────────────────────────────────────────────────
bool SendRegistration()
{
    if (!te::sdk::LocalClient)
    {
        Log("[sw_ac_emu] SendRegistration: LocalClient not ready");
        return false;
    }
    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F0);
    WriteLE32(bs, SWAC_MAGIC);
    WriteLE32(bs, SWAC_VERSION);
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    Log("[sw_ac_emu] SendRegistration -> %s", ok ? "ok" : "FAIL");
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
    if (!message || !*message)
    {
        Log("[sw_ac_emu] SendACMessage: empty message");
        return false;
    }
    const size_t len = std::strlen(message);
    if (len > MAX_MSG_LEN)
    {
        Log("[sw_ac_emu] SendACMessage: too long (%zu > %zu)", len, MAX_MSG_LEN);
        return false;
    }
    RakNet::BitStream bs;
    WriteLE16(bs, 0x00F2);
    WriteLE16(bs, static_cast<uint16_t>(len + 1));
    bs.Write(message, static_cast<int>(len + 1));
    const bool ok = te::sdk::LocalClient->SendPacket(&bs, MEDIUM_PRIORITY, RELIABLE_ORDERED, 0);
    Log("[sw_ac_emu] SendACMessage('%s') len=%zu -> %s", message, len, ok ? "ok" : "FAIL");
    return ok;
}

// ── Challenge-response hash (reverse-engineered from 0x100510E6) ──────────────
uint32_t compute_response(uint32_t c)
{
    uint32_t eax = (c ^ 0x4c797c0fu) + 0x13579bdu + ((c ^ 0x408000u) << 5);
    uint32_t ecx = c ^ 0x1020000u;
    uint32_t edx = ((eax << 7) + 0x2468aceu) ^ eax;
    edx += (c << 11) ^ 0x10203040u;
    edx += (ecx << 5) + ecx;       // 33 * ecx
    uint32_t esi = (edx << 13) ^ edx;
    esi ^= 0x88cb5573u;
    esi += 0x6a7a5a5u;
    if (esi == 0)
        esi = c ^ 0x6d2b79f5u;
    return esi;
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
    Log("[sw_ac_emu] SendChallengeResponse(ch=0x%08X resp=0x%08X uptime=%u) -> %s",
        challenge, response, uptime, ok ? "ok" : "FAIL");
    return ok;
}

// ── Parse raw packet bytes for an incoming 0xF3 SWAC challenge ───────────────
// Returns true + sets challenge_out on success.
// Handles direct [0xF3][0x00][SWAC][challenge]
// and SA-MP 0x28-wrapped [0x28][4][0xF3][0x00][SWAC][challenge].
bool TryParseChallenge(const uint8_t* raw, int len, uint32_t& challenge_out)
{
    auto readLE32 = [&](int off) -> uint32_t {
        return uint32_t(raw[off])
             | uint32_t(raw[off + 1]) <<  8
             | uint32_t(raw[off + 2]) << 16
             | uint32_t(raw[off + 3]) << 24;
    };

    int dataOff = -1;
    if      (len >= 10 && raw[0] == 0xF3 && raw[1] == 0x00)                      dataOff = 2;
    else if (len >= 15 && raw[0] == 0x28 && raw[5] == 0xF3 && raw[6] == 0x00)    dataOff = 7;

    if (dataOff < 0 || len < dataOff + 8)
        return false;
    if (readLE32(dataOff) != SWAC_MAGIC)
    {
        Log("[sw_ac_emu] TryParseChallenge: bad SWAC magic (got 0x%08X)", readLE32(dataOff));
        return false;
    }
    challenge_out = readLE32(dataOff + 4);
    return true;
}

// ── Incoming packet handler ───────────────────────────────────────────────────
bool OnIncomingPacket(const te::sdk::PacketContext& ctx)
{
    if (ctx.packetId == uint32_t(ID_CONNECTION_REQUEST_ACCEPTED))
    {
        if (g_sentOnThisConnect.exchange(true))
            return true;
        g_connectTime = GetTickCount();
        Log("[sw_ac_emu] Connected - registering with SWAC server");
        std::thread([]() {
            // Minimal delay — just enough to let SA-MP's own handshake finish.
            // Sending 0xF0 ASAP so SW:AC.asi sets the auth flag before spawn.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            SendRegistration();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            SendACMessage("hello");
        }).detach();
        return true;
    }

    if (ctx.packetId == uint32_t(ID_DISCONNECTION_NOTIFICATION) ||
        ctx.packetId == uint32_t(ID_CONNECTION_LOST))
    {
        g_sentOnThisConnect.store(false);
        g_connectTime = 0;
        Log("[sw_ac_emu] Disconnected - will re-register on next connect");
        return true;
    }

    // Detect SWAC challenge: direct (0xF3) or SA-MP 0x28-wrapped
    if (ctx.packetId == 0xF3 || ctx.packetId == 0x28)
    {
        auto* bs        = static_cast<RakNet::BitStream*>(ctx.bitStream);
        const uint8_t* raw = bs->GetData();
        const int      rlen = bs->GetNumberOfBytesUsed();

        uint32_t challenge = 0;
        if (TryParseChallenge(raw, rlen, challenge))
            SendChallengeResponse(challenge);
    }

    return true;
}

} // namespace

void InstallHooks()
{
    te::sdk::RegisterRaknetCallback(HookType::IncomingPacket, OnIncomingPacket);

    // /acmsg <text>  —  manually fire an AC message
    te::sdk::helper::samp::RegisterChatCommand("acmsg", [](const char* params) {
        if (!params || !*params)
        {
            te::sdk::helper::samp::AddChatMessage(
                "[sw_ac_emu] Usage: /acmsg <message>", 0xFFFFAA00);
            return;
        }
        std::string msg(params);
        const size_t start = msg.find_first_not_of(" \t");
        if (start == std::string::npos)
        {
            te::sdk::helper::samp::AddChatMessage(
                "[sw_ac_emu] Usage: /acmsg <message>", 0xFFFFAA00);
            return;
        }
        if (start > 0)
            msg.erase(0, start);
        SendACMessage(msg.c_str());
    });

    Log("[sw_ac_emu] Hooks installed (IncomingPacket + /acmsg)");
}
