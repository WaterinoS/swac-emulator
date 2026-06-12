#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <chrono>
#include <thread>

#include "te-sdk.h"

#include "sender.h"
#include "log.h"

namespace {

DWORD WINAPI InitThread(LPVOID)
{
    LogInit();
    Log("sw_ac_emu.asi loaded - waiting for SAMP RakNet hooks");

    int waitTicks = 0;
    while (!te::sdk::InitRakNetHooks())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (++waitTicks % 50 == 0)
            Log("Still waiting for SAMP/RakNet... (%d s)", waitTicks / 10);
    }

    Log("RakNet hooks ready - installing callbacks");
    InstallHooks();
    Log("sw_ac_emu init done");
	te::sdk::helper::samp::AddChatMessage("[ #TE ] SW-AC Emulator v1.3 by WaterSmoke Loaded !", 0xFF00FF00u);
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hMod);
        if (HANDLE h = CreateThread(nullptr, 0, &InitThread, nullptr, 0, nullptr))
            CloseHandle(h);
    }
    return TRUE;
}