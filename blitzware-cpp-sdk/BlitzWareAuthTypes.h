#pragma once
#include <string>
#include <vector>

namespace BlitzWareAuth {
    struct AuthResult {
        bool success;
        long errorCode;
        std::wstring message;
    };

    struct AuthConfig {
        std::wstring clientId;
        std::wstring redirectUri = L"http://localhost:8080/";
        std::wstring authServer = L"https://auth.blitzware.xyz/api/auth";
    };

    enum class AuthError {
        Success = 0,
        InvalidState,
        NetworkError,
        TokenExpired,
        InvalidToken,
        UserCancelled,
        StorageError
    };
}