#include "log.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

namespace {

std::mutex g_logMtx;
std::string g_logPath;

std::string ResolveLogPath()
{
    char buf[MAX_PATH] = {};
    HMODULE hSelf = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&ResolveLogPath), &hSelf);

    if (!hSelf || !GetModuleFileNameA(hSelf, buf, MAX_PATH))
        return "sw_ac_emu.log";

    std::string p(buf);
    auto slash = p.find_last_of("\\/");
    if (slash != std::string::npos)
        p.resize(slash + 1);
    p += "sw_ac_emu.log";
    return p;
}

} // namespace

void LogInit()
{
    std::lock_guard<std::mutex> lk(g_logMtx);
    g_logPath = ResolveLogPath();

    if (FILE* f = std::fopen(g_logPath.c_str(), "w"))
    {
        std::fprintf(f, "==== sw_ac_emu log start ====\n");
        std::fclose(f);
    }
}

void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lk(g_logMtx);

    if (g_logPath.empty())
        g_logPath = ResolveLogPath();

    FILE* f = std::fopen(g_logPath.c_str(), "a");
    if (!f) return;

    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::fprintf(f, "[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);

    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);

    std::fputc('\n', f);
    std::fclose(f);
}
