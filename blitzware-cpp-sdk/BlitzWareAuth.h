#pragma once
#include "BlitzWareAuthTypes.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <string>
#include <windows.h>
#include <mutex>
#include <wincred.h>
#include <unordered_map>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace BlitzWareAuth {
    class AuthManager {
    public:
        static AuthManager& GetInstance();

        AuthResult Initialize(const AuthConfig& config);
        AuthResult Login(bool useEmbeddedBrowser = false);
        AuthResult Logout();
        bool IsAuthenticated();

    private:
        AuthManager() = default;
        ~AuthManager() = default;

        void StartLocalServer();
        void StopLocalServer();
        std::wstring GenerateState();
        AuthError ConvertWinError(DWORD winError);

        AuthConfig m_config;
        AuthError m_lastError = AuthError::Success;

        std::wstring m_state;
        std::wstring m_receivedAccessToken;
        std::wstring m_receivedRefreshToken;

        std::atomic<bool> m_serverRunning{ false };
        std::mutex m_mutex;
        std::condition_variable m_cv;
    };
}