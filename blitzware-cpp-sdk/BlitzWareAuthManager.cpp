#include "BlitzWareAuth.h"

namespace BlitzWareAuth {
    AuthManager& AuthManager::GetInstance() {
        static AuthManager instance;
        return instance;
    }

    AuthResult AuthManager::Initialize(const AuthConfig& config) {
        m_config = config;
        PCREDENTIALW pcred;
        if (CredReadW(L"BlitzWareAuth_AccessToken", CRED_TYPE_GENERIC, 0, &pcred)) {
            std::wstring token(reinterpret_cast<wchar_t*>(pcred->CredentialBlob),
                pcred->CredentialBlobSize / sizeof(wchar_t));
			std::wstring refreshToken(reinterpret_cast<wchar_t*>(pcred->CredentialBlob),
				pcred->CredentialBlobSize / sizeof(wchar_t));
            CredFree(pcred);
			m_receivedAccessToken = token;
        }
        if (CredReadW(L"BlitzWareAuth_RefreshToken", CRED_TYPE_GENERIC, 0, &pcred)) {
            std::wstring token(reinterpret_cast<wchar_t*>(pcred->CredentialBlob),
                pcred->CredentialBlobSize / sizeof(wchar_t));
            CredFree(pcred);
            m_receivedRefreshToken = token;
        }
        return { true, S_OK, L"Initialized" };
    }

    AuthResult AuthManager::Login(bool useEmbeddedBrowser) {
        m_state = GenerateState();

        StartLocalServer();

        std::wstringstream authUrl;
        authUrl << m_config.authServer << L"/authorize?"
            << L"response_type=token&"
            << L"client_id=" << m_config.clientId << L"&"
            << L"redirect_uri=" << m_config.redirectUri << L"&"
            << L"state=" << m_state;

        ShellExecuteW(nullptr, L"open", authUrl.str().c_str(), nullptr, nullptr, SW_SHOWNORMAL);

        std::unique_lock<std::mutex> lock(m_mutex);
        bool received = m_cv.wait_for(lock, std::chrono::seconds(30), [this]() {
            return !m_receivedAccessToken.empty();
            });
        StopLocalServer();

        if (!received) {
            m_lastError = AuthError::UserCancelled;
            return { false, E_FAIL, L"Login timed out" };
        }

        // Store tokens and fetch user info
        CREDENTIALW cred = { 0 };
        cred.Type = CRED_TYPE_GENERIC;
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        // Access Token
        wchar_t targetAccess[] = L"BlitzWareAuth_AccessToken";
        cred.TargetName = targetAccess;
        std::wstring accessTokenCopy = m_receivedAccessToken;
        cred.CredentialBlob = reinterpret_cast<LPBYTE>(&accessTokenCopy[0]);
        cred.CredentialBlobSize = static_cast<DWORD>(accessTokenCopy.size() * sizeof(wchar_t));
        if (!CredWriteW(&cred, 0)) {
            m_lastError = ConvertWinError(GetLastError());
            return { false, HRESULT_FROM_WIN32(GetLastError()), L"Failed to store access token" };
        }

        // Refresh Token
        wchar_t targetRefresh[] = L"BlitzWareAuth_RefreshToken";
        cred.TargetName = targetRefresh;
        std::wstring refreshTokenCopy = m_receivedRefreshToken;
        cred.CredentialBlob = reinterpret_cast<LPBYTE>(&refreshTokenCopy[0]);
        cred.CredentialBlobSize = static_cast<DWORD>(refreshTokenCopy.size() * sizeof(wchar_t));

        if (!CredWriteW(&cred, 0)) {
            m_lastError = ConvertWinError(GetLastError());
            return { false, HRESULT_FROM_WIN32(GetLastError()), L"Failed to store refresh token" };
        }

		return { true, S_OK, L"Login successful" };
    }

    AuthResult AuthManager::Logout() {
        // Clear stored tokens
        if (!CredDeleteW(L"BlitzWareAuth_AccessToken", CRED_TYPE_GENERIC, 0)) {
            DWORD error = GetLastError();
            if (error != ERROR_NOT_FOUND) { // Ignore if token doesn't exist
                m_lastError = ConvertWinError(error);
                return { false, HRESULT_FROM_WIN32(error), L"Failed to delete access token" };
            }
        }

        if (!CredDeleteW(L"BlitzWareAuth_RefreshToken", CRED_TYPE_GENERIC, 0)) {
            DWORD error = GetLastError();
            if (error != ERROR_NOT_FOUND) {
                m_lastError = ConvertWinError(error);
                return { false, HRESULT_FROM_WIN32(error), L"Failed to delete refresh token" };
            }
        }

        // Clear internal state
        m_receivedAccessToken.clear();
        m_receivedRefreshToken.clear();
        m_state.clear();

        return { true, S_OK, L"Logged out successfully" };
    }

	bool AuthManager::IsAuthenticated() {
		PCREDENTIALW pcred;
		if (CredReadW(L"BlitzWareAuth_AccessToken", CRED_TYPE_GENERIC, 0, &pcred)) {
			CredFree(pcred);
			return true;
		}
		return false;
	}

	std::wstring AuthManager::GenerateState() {
		const std::wstring chars = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		std::wstring state;
		for (int i = 0; i < 16; ++i) {
			state += chars[rand() % chars.size()];
		}
		return state;
	}

    void AuthManager::StartLocalServer() {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            m_lastError = AuthError::NetworkError;
            return;
        }

        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in service = {};
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = 0;
        inet_pton(AF_INET, "127.0.0.1", &service.sin_addr);
        service.sin_port = htons(8080);

        bind(listenSocket, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
        listen(listenSocket, 1);

        m_serverRunning = true;
        std::thread([this, listenSocket]() {
            while (m_serverRunning) {
                sockaddr_in clientAddr;
                int addrLen = sizeof(clientAddr);
                SOCKET client = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
                if (client == INVALID_SOCKET) break;

                char buffer[2048] = { 0 };
                int bytes = recv(client, buffer, sizeof(buffer) - 1, 0);
                if (bytes > 0) {
                    std::string request(buffer);
                    // Parse GET /?access_token=...&refresh_token=...
                    size_t qsPos = request.find("GET /");
                    if (qsPos != std::string::npos) {
                        size_t start = request.find("?", qsPos);
                        size_t end = request.find(' ', start);
                        std::string qs = request.substr(start + 1, end - start - 1);

                        // Split into key=value pairs
                        std::unordered_map<std::string, std::string> params;
                        size_t pos = 0;
                        while (pos < qs.size()) {
                            size_t amp = qs.find('&', pos);
                            std::string pair = qs.substr(pos, amp - pos);
                            size_t eq = pair.find('=');
                            if (eq != std::string::npos) {
                                params[pair.substr(0, eq)] = pair.substr(eq + 1);
                            }
                            if (amp == std::string::npos) break;
                            pos = amp + 1;
                        }

                        // Convert to wstring
                        auto toW = [](const std::string& s) {
                            return std::wstring(s.begin(), s.end());
                            };

                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_receivedAccessToken = toW(params["access_token"]);
                            m_receivedRefreshToken = toW(params["refresh_token"]);
                            m_cv.notify_one();
                        }
                    }

                    // Send simple HTTP response
                    const char* response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<html><body>Authentication complete. You may close this window.</body></html>";
                    send(client, response, static_cast<int>(strlen(response)), 0);
                }
                closesocket(client);
                break; // handle only one request
            }
            closesocket(listenSocket);
            WSACleanup();
            }).detach();
    }

    void AuthManager::StopLocalServer() {
        m_serverRunning = false;
    }

	AuthError AuthManager::ConvertWinError(DWORD winError) {
		switch (winError) {
		case ERROR_SUCCESS:
			return AuthError::Success;
		case ERROR_INVALID_PARAMETER:
			return AuthError::InvalidState;
		case ERROR_NOT_FOUND:
			return AuthError::TokenExpired;
		case ERROR_NO_TOKEN:
			return AuthError::InvalidToken;
		default:
			return AuthError::NetworkError;
		}
	}
}
