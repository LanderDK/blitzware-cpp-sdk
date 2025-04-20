#include <iostream>
#include "../blitzware-cpp-sdk/BlitzWareAuth.h"

int main() {
    BlitzWareAuth::AuthConfig config = { L"client_id" };

    auto& auth = BlitzWareAuth::AuthManager::GetInstance();
    auth.Initialize(config);

    std::wcout << L"1. Login\n2. Logout\n3. Check Auth\n4. Exit\nChoice: ";
    int choice;
    std::cin >> choice;

    switch (choice) {
    case 1: {
        auto result = auth.Login();
        std::wcout << (result.success ? L"Login successful: " : L"Login failed: ")
            << result.message << L"\n";
        break;
    }
    case 2: {
        auth.Logout();
        std::wcout << L"Logged out\n";
        break;
    }
    case 3: {
        std::wcout << (auth.IsAuthenticated() ? L"Authenticated" : L"Not authenticated")
            << L"\n";
        break;
    }
    case 4:
        return 0;
    }

    system("pause");
    return 0;
}