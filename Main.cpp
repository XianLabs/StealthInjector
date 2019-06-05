#include <windows.h> 
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <string>
#include <stdio.h> 
#include <Shlwapi.h>
#define WIN32_LEAN_AND_MEAN 
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 
#pragma comment(lib,"Shlwapi.lib")


BOOL Inject(DWORD pID, const char * DLL_NAME)
{
	HANDLE Proc;
	char buf[50] = { 0 };
	LPVOID RemoteString, LoadLibAddy;

	if (!pID)
		return false;

	Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (!Proc)
	{
		sprintf(buf, "OpenProcess() failed: %d\n", GetLastError());
		printf(buf);
		return false;
	}

	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	// Allocate space in the process for our DLL 
	RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Write the string name of our DLL in the memory allocated 
	WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

	// Load our DLL 
	CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

	CloseHandle(Proc);
	return true;
}

DWORD GetTargetThreadIDFromProcName(const wchar_t * ProcName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;
	int injected = 0;
	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		//MessageBox(NULL, "Error: Unable <strong class="highlight">to</strong> create toolhelp snapshot!", "2MLoader", MB_OK); 
		printf("Error: Unable <strong class=\"highlight\">to</strong> create toolhelp snapshot!");
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (StrStrIW(pe.szExeFile, ProcName) != NULL)
		{
			char buf[MAX_PATH] = { 0 };
			GetFullPathNameA("BoE.dll", MAX_PATH, buf, NULL);
			Inject(pe.th32ProcessID, buf);
			//return pe.th32ProcessID;
			injected = 1;
		}
		retval = Process32Next(thSnapShot, &pe);
	}
	return injected;
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

BOOL AttemptMulti(LPSTR MutexName)
{
	HANDLE hMutex = OpenMutexA(
		SYNCHRONIZE, TRUE, (MutexName));
	//Make sure of a successful mutex creation.

	if (hMutex != NULL)
	{
		DWORD pID = FindProcessId(L"PathOfExile_x64.exe");
		printf("pID: %d\n", pID);
		HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pID);
		printf("Proc handle: %d\n", Proc);
		HANDLE DupHandle = NULL;
		BOOL Success = DuplicateHandle(Proc, hMutex, GetCurrentProcess(), &DupHandle, 0, TRUE, DUPLICATE_SAME_ACCESS);

		if (Success)
		{
			printf("Handle: %d\n", DupHandle);

			if (CloseHandle(DupHandle) == FALSE)
			{
				int Error = GetLastError();
				MessageBoxA(0, "Close handle failed!", 0, 0);
				char buf[20];
				itoa(Error, buf, 10);
				MessageBoxA(0, buf, 0, 0);
				return FALSE;
			}
			else
				printf("Closehandle return: %d\n", GetLastError());
		}			
		else
			printf("DuplicateHandle failed! %d\n", GetLastError());

	}
	if (hMutex == NULL)
	{
		printf("Null mutex: %d\n", GetLastError());

		//Mutex creation failed.  Use GetLastError() and FormatMessage() to learn why it failed.
		return FALSE; //Or return a failure code, or whatever applies to your case.
	}

	return TRUE;
}

int main(int argc, char** argv)
{
	
	bool injected = false;
	EnableDebugPriv();
	//AttemptMulti("PathOfExileSingleInstance");

	while (!injected)
	{
		// Retrieve process ID 
		DWORD pID = GetTargetThreadIDFromProcName(L"YOURPROCESS.exe");
	
		if (pID)
		{
			injected = true;
			printf("Injected!\n");
		}
		else
			printf("Waiting to inject...\n");
	}
	
	return 0;
}