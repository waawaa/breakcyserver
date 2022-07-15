#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <windows.h>

#pragma comment(lib, "Dbghelp.lib")

#pragma comment(lib, "ntdll.lib")



/*IOCTL to interrogate procexp driver*/
#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 0x8335003c 
#define IOCTL_DUPLICATE_TOKEN 0x8335000c
#define IOCTL_CLOSE_HANDLE 0x83350004

/*Ask about protection of process*/
#define ProcessProtectionInformation 0x61

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

/*Define Errors NT_SUCCESS and so*/
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1


typedef enum _PS_PROTECTED_TYPE : UCHAR
{
    PsProtectedTypeNone,
    PsProtectedTypeProtectedLight,
    PsProtectedTypeProtected,
    PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER : UCHAR
{
    PsProtectedSignerNone,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION
{
    union
    {
        struct
        {
            PS_PROTECTED_TYPE Type : 3;
            BOOLEAN Audit : 1;
            PS_PROTECTED_SIGNER Signer : 4;
        } s;
        UCHAR Level;
    };
} PS_PROTECTION, * PPS_PROTECTION;
//
/*Protection codes*/

//
void _PRINT(BYTE X) {
    if (X == 0x72)
        puts("PS_PROTECTED_SYSTEM");
    if (X == 0x62)
        puts("PS_PROTECTED_WINTCB");
    if (X == 0x61)
        puts("PS_PROTECTED_WINTCB_LIGHT");
    if (X == 0x52)
        puts("PS_PROTECTED_WINDOWS");
    if (X == 0x51)
        puts("PS_PROTECTED_WINDOWS_LIGHT");
    if (X == 0x41)
        puts("PS_PROTECTED_LSA_LIGHT");
    if (X == 0x31)
        puts("PS_PROTECTED_ANTIMALWARE_LIGHT");
    if (X == 0x12)
        puts("PS_PROTECTED_AUTHENTICODE");
    if (X == 0x11)
        puts("PS_PROTECTED_AUTHENTICODE_LIGHT");
    if (X == 0)
        puts("PS_PROTECTED_NONE");
}
/*Define NtQuerySystemInformation*/
using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONGLONG SystemInformationClass,
    PVOID SystemInformation,
    ULONGLONG SystemInformationLength,
    PULONGLONG ReturnLength
    );

/*Define NtQueryProcessInformation*/

using fNtQueryProcessInformation = NTSTATUS(WINAPI*)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);
// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT Handle;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    long NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


/*SeDebugPrivilege to be able to create a handle to de driver etc*/
BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	const wchar_t* lpwPriv = L"SeDebugPrivilege";
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpwPriv,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}