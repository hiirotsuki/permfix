#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#ifdef _MSC_VER
#pragma comment(linker, "/ENTRY:mainCRTStartup")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/subsystem:console")
#endif

PSID g_PSID = NULL;
PSID g_UsersSID = NULL;

#define LOG_BUFFER_SIZE 1024
#define UTF8_BUFFER_SIZE ((LOG_BUFFER_SIZE * 4) + 1)

wchar_t *xstrchrW(const wchar_t *s, int c)
{

	for(; *s != '\0' && *s != c; s++)
		;

	return *s == c ? (wchar_t *)s : NULL;
}

static HANDLE GetStdOutHandle(void)
{
	static HANDLE hStdOut = INVALID_HANDLE_VALUE;
	if(hStdOut == INVALID_HANDLE_VALUE)
	{
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}
	return hStdOut;
}

static void LogW(LPCWSTR format, ...)
{
	WCHAR buffer[LOG_BUFFER_SIZE];
	char utf8[UTF8_BUFFER_SIZE];
	va_list args;
	va_start(args, format);

	int len = wvsprintfW(buffer, format, args);
	va_end(args);

	if(len > 0)
	{
		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buffer, len, utf8, sizeof(utf8), NULL, NULL);
		if(utf8Len > 0)
		{
			DWORD written;
			WriteFile(GetStdOutHandle(), utf8, utf8Len, &written, NULL);
		}
	}
}

static PSID GetSID(LPCWSTR accountName)
{
	PSID pSID = NULL;
	DWORD sidSize = 0;
	DWORD domainSize = 0;
	WCHAR domainName[256];
	SID_NAME_USE sidType;
	HANDLE heap = GetProcessHeap();

	LookupAccountNameW(NULL, accountName, NULL, &sidSize, domainName, &domainSize, &sidType);
	if(sidSize == 0)
	{
		LogW(L"Failed to get SID size\r\n");
		return NULL;
	}

	pSID = HeapAlloc(heap, HEAP_ZERO_MEMORY, sidSize);
	if(!pSID)
	{
		LogW(L"Failed to allocate memory for SID\r\n");
		return NULL;
	}

	if(!LookupAccountNameW(NULL, accountName, pSID, &sidSize, domainName, &domainSize, &sidType))
	{
		LogW(L"Failed to lookup account name for %ls: %lu\r\n", accountName, GetLastError());
		HeapFree(heap, 0, pSID);
		return NULL;
	}

	return pSID;
}

static void SetOwner(LPCWSTR path)
{
	if(SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, g_PSID, NULL, NULL, NULL) != ERROR_SUCCESS)
		LogW(L"Failed to set owner: %lu\r\n", GetLastError());
}

void SetPermissions(LPCWSTR path)
{
	PACL pACL = NULL;
	EXPLICIT_ACCESS_W ea[2];

	ea[0].grfAccessPermissions = GENERIC_ALL;
	ea[0].grfAccessMode = GRANT_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[0].Trustee.ptstrName = (LPWSTR)g_UsersSID;
	ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	ea[0].Trustee.pMultipleTrustee = NULL;

	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = GRANT_ACCESS;
	ea[1].grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPWSTR)g_UsersSID;
	ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	ea[1].Trustee.pMultipleTrustee = NULL;

	DWORD result = SetEntriesInAclW(2, ea, NULL, &pACL);
	if(result != ERROR_SUCCESS)
	{
		LogW(L"SetEntriesInAcl failed: %lu\r\n", result);
		return;
	}

	// Set the DACL for the object with inheritance flags
	DWORD flags = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
	result = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, flags, NULL, NULL, pACL, NULL);
	if(result != ERROR_SUCCESS)
		LogW(L"SetNamedSecurityInfo failed: %lu\r\n", result);

	if(pACL)
		LocalFree(pACL);
}

void FixPermissionsRecursively(LPCWSTR path)
{
	WCHAR searchPath[MAX_PATH];
	WIN32_FIND_DATAW findFileData;
	HANDLE hFind;

	LogW(L"\nProcessing directory: %ls", path);

	SetOwner(path);
	SetPermissions(path);

	wsprintfW(searchPath, L"%ls\\*", path);
	hFind = FindFirstFileW(searchPath, &findFileData);

	if(hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if(lstrcmpW(findFileData.cFileName, L".") != 0 && \
				lstrcmpW(findFileData.cFileName, L"..") != 0)
			{
				WCHAR fullPath[MAX_PATH];
				wsprintfW(fullPath, L"%ls\\%ls", path, findFileData.cFileName);

				LogW(L"\nProcessing %ls...", fullPath);

				if(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					FixPermissionsRecursively(fullPath);
				}
				else
				{
					SetOwner(fullPath);
					SetPermissions(fullPath);
				}
			}
		}
		while(FindNextFileW(hFind, &findFileData) != 0);
		FindClose(hFind);
	}
	else
	{
		LogW(L"Failed to find files in directory: %lu\r\n", GetLastError());
	}
}

int mainCRTStartup(void)
{
	LPWSTR p, args;
	LPWSTR directory = NULL;
	HANDLE hToken;
	struct
	{
		DWORD PrivilegeCount;
		LUID_AND_ATTRIBUTES Privileges[5];
	} tkp;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		LogW(L"OpenProcessToken failed: %lu\r\n", GetLastError());
		ExitProcess(1);
	}

	LPCWSTR privileges[] =
	{
		L"SeTakeOwnershipPrivilege",
		L"SeSecurityPrivilege",
		L"SeBackupPrivilege",
		L"SeRestorePrivilege",
		L"SeChangeNotifyPrivilege"
	};

	DWORD privilegeCount = sizeof(privileges) / sizeof(privileges[0]);
	tkp.PrivilegeCount = privilegeCount;

	for(DWORD i = 0; i < privilegeCount; i++)
	{
		if(!LookupPrivilegeValueW(NULL, privileges[i], &tkp.Privileges[i].Luid))
		{
			LogW(L"LookupPrivilegeValue failed: %lu\r\n", GetLastError());
			CloseHandle(hToken);
			ExitProcess(1);
		}
		tkp.Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
	}

	if(!AdjustTokenPrivileges(hToken, FALSE, (PTOKEN_PRIVILEGES)&tkp, sizeof(tkp), NULL, NULL))
	{
		LogW(L"AdjustTokenPrivileges failed: %lu\r\n", GetLastError());
		CloseHandle(hToken);
		ExitProcess(1);
	}

	DWORD error = GetLastError();
	if(error == ERROR_NOT_ALL_ASSIGNED)
	{
		LogW(L"Warning: Not all privileges were assigned. Run as administrator.\r\n");
		CloseHandle(hToken);
		ExitProcess(1);
	}

	args = GetCommandLineW();

	p = xstrchrW(args, ' ');

	if(!p)
	{
		LogW(L"Usage: %ls <directory>\r\n", args);
		CloseHandle(hToken);
		ExitProcess(1);
	}

	directory = p + 1;

	// Convert relative path to absolute path
	WCHAR fullPath[MAX_PATH];
	if(GetFullPathNameW(directory, MAX_PATH, fullPath, NULL) == 0)
	{
		LogW(L"Failed to get full path: %lu\r\n", GetLastError());
		CloseHandle(hToken);
		ExitProcess(1);
	}

	DWORD attrs = GetFileAttributesW(fullPath);
	if(attrs == INVALID_FILE_ATTRIBUTES)
	{
		LogW(L"Directory does not exist or cannot be accessed: %lu\r\n", GetLastError());
		CloseHandle(hToken);
		ExitProcess(1);
	}

	LogW(L"Beginning to fix permissions for %ls...\r\n", fullPath);
	g_PSID = GetSID(L"Administrator");
	g_UsersSID = GetSID(L"Users");
	FixPermissionsRecursively(fullPath);

	CloseHandle(hToken);
	HeapFree(GetProcessHeap(), 0, g_PSID);
	HeapFree(GetProcessHeap(), 0, g_UsersSID);
	ExitProcess(0);
}
