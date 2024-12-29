#include <Windows.h>

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
) {
    return MessageBoxA(NULL, "Hello World!", "Hello World!", MB_OK | MB_ICONINFORMATION);
}
