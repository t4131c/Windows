#define SECURITY_WIN32	// to access the security API from a user-mode app
#define BUILD_WINDOWS	// to not show the deprecated error
#include <windows.h>	//windows-specific header which contains declarations for all of the functions in the windows API
#include <stdio.h>	// to use standart input/output
#include <Security.h>	// to use GetComputerObjectName
#include <Secext.h>	// 
#include <wchar.h>	//	to use wchar
#include <tchar.h>	// to use tchar
#include <sysinfoapi.h>	//	to use system service	
#include <versionhelpers.h>	//to use IsWindowsXXOrGreater and VerifyVersionInfo

#pragma comment(lib, "Secur32.lib")	//to link against Secur32.lib

bool err_print(DWORD e) {	//print error message
	LPWSTR text;	//buffer to store error message
	DWORD chars = ::FormatMessage(	//to format a message string
		FORMAT_MESSAGE_ALLOCATE_BUFFER | // function allocates
		FORMAT_MESSAGE_FROM_SYSTEM |	//to bring error message from OS
		FORMAT_MESSAGE_IGNORE_INSERTS,	//if the message is not found in the module specified by lpSource. This flag cannot be used wit
		nullptr, e, 0,	//location of the message definition, message identifier for the requested message, language identifier for the requested message.
		(LPWSTR)&text, // buffer to receive formatted message
		100, nullptr);	//size, arguments
	if (chars > 0) {	// if success(return length>0)
		printf(" [!] Error %d: %ws", e, text);	// print error message
		::LocalFree(text);	//free allocated buffer
		return true;	//return True to announce the success
	}
	else {	//	if failed
		printf("No such error exists\n");	
		return false;	//return false to announce the fail
	}
}

int main()
{
	printf("------------------------------------------------------------------------------------------------------------\n");
	// 1. Print information about your system by calling the following APIs

	//  Print information about your system by calling GetNativeSystemInfo
	printf("[*] Print information about your system by calling GetNativeSystemInfo\n");
	SYSTEM_INFO si;	//	pointer to a SYSTEM_INFO structure that receives the information
	::GetNativeSystemInfo(&si);	//Retrieves information about the current system to an application and store it si
	//print recieved informations
	printf(" - Number of Logical Processors: %d\n", si.dwNumberOfProcessors);
	printf(" - Page size: %d Bytes\n", si.dwPageSize);
	printf(" - Processor Mask: 0x%p\n", (PVOID)si.dwActiveProcessorMask);
	printf(" - Minimum process address: 0x%p\n", si.lpMinimumApplicationAddress);
	printf(" - Maximum process address: 0x%p\n", si.lpMaximumApplicationAddress);
	printf(" - Number of logical processors: %d\n", si.dwNumberOfProcessors);
	printf(" - Processor Type: %d\n", si.dwProcessorType);
	printf("------------------------------------------------------------------------------------------------------------\n");


	//  Print information about your system by calling GetComputerName
	printf("[*] Print information about your system by calling GetComputerName\n");
	//MAX_COMPUTERNAME_LENGTH is defined max value
	WCHAR computername[MAX_COMPUTERNAME_LENGTH + 1];	//	buffer that receives the computer name or the cluster virtual server name
	DWORD namesize = MAX_COMPUTERNAME_LENGTH + 1;	//specifies the size of the buffer
	if (!::GetComputerName(computername, &namesize)) {	//retrieves the NetBIOS name of the local computer 
		err_print(::GetLastError());	//if it returns false, call err_print to print error message
	}
	else {	//if it returns true(success)
		printf(" - ComputerName : %ls\n", computername);	//print recieved computername, use "%ls" to print wchar type
	}
	printf("------------------------------------------------------------------------------------------------------------\n");


	//  Print information about your system by calling GetComputerObjectName
	printf("[*] Print information about your system by calling GetComputerObjectName\n");
	WCHAR objname[512];	//	buffer to recieve computerobjectname(local computer's name) in specified format
	ULONG objnamesize = sizeof(objname);	//specifies the size
	//NameDnsDomain is one of the format for the name
	if (!GetComputerObjectName(NameDnsDomain, objname, &objnamesize)) {	//Retrieves the local computer's name in a specified format NameDnsDomain.
		err_print(::GetLastError());	//if it returns false, call err_print to print error message

	}
	else {	//if it returns true(success)
		printf(" - ComputerObjectName : %ls\n", objname);	//	print local computer's name, use "%ls" to print wchar type
	}
	printf("------------------------------------------------------------------------------------------------------------\n");


	//  Print information about your system by calling GetWindowsDirectory
	printf("[*] Print information about your system by calling GetWindowsDirectory\n");
	WCHAR windir[MAX_PATH];	//	buffer to recieve windowsdirectory
	if (!::GetWindowsDirectory(windir, MAX_PATH)) {	//Retrieves the path of the Windows directory
		err_print(::GetLastError());	//if it returns false, call err_print to print error message
	}
	else {	//if it returns true(success)
		printf(" - WindowsDirectory : %ls\n", windir);	//	print recieved windowdirectory, use "%ls" to print wchar type
	}
	printf("------------------------------------------------------------------------------------------------------------\n");


	//  Print information about your system by calling GetProductInfo
	printf("[*] information about your system by calling GetProductInfo\n");

	auto sharedUserData1 = (BYTE*)0x7FFE0000;	// to get current os version. In this code, I used sharedUserData because there was a problem with GetVersionEx after window 8.1
	DWORD dwPInfo = NULL;	//	to recieve os type
	//input datas are osmajorversion, osminorversion, spmajorversion, spminorversion, output
	if (!::GetProductInfo(*(ULONG*)(sharedUserData1 + 0x26c), *(ULONG*)(sharedUserData1 + 0x270), 0, 0, &dwPInfo)) {	//	Retrieves the product type for the operating system on the local computer
		err_print(::GetLastError());	//if it returns false, call err_print to print error message
	}
	else {
		printf(" - Product Type : %d\n", dwPInfo);	//	print product type
	}
	printf("------------------------------------------------------------------------------------------------------------\n");



	//	2. Print the exact Windows version of your system

	//	Getting the Windows version using GetVersionEx with a manifest file
	printf("[*] Getting the Windows version using GetVersionEx with a manifest file\n");
	OSVERSIONINFO vi = { sizeof(vi) };	// to set the dwOSVersionInfoSize member of the structure
	::GetVersionEx(&vi);	//	recieve os version and store it vi. If you run an application in compatible mode, the GetVersionEx will select window version in compatible mod instead of current window version
	//print majorversion, minorversion, buildnumber
	printf(" - Version: %d.%d.%d\n", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);	//GetVersionExA may be altered or unavailable for releases after Windows 8.1. if windows 10, it returns 6.2(Windows 8 version)
	printf(" - OS platform: %d\n", vi.dwPlatformId);	//print os platform
	printf("------------------------------------------------------------------------------------------------------------\n");


	//	Getting the Windows version using ‘versionhelpers.h’ and VerifyVersionInfo with a manifest file
	printf("[*] Getting the Windows version using 'versionhelpers.h' with a manifest file\n");
	if (IsWindowsVistaOrGreater()) {	//current OS version is greater than windows Vista? return true when it's true
		printf(" - Current OS version is greater than Windows Vista\n");
	}
	else {
		printf(" - Current OS version matches Windows Vista\n");
	}

	if (IsWindowsXPOrGreater()) {	//current OS version is greater than windows XP? return true when it's true
		printf(" - Current OS version is greater than Windows XP\n");
	}
	else {
		printf(" - Current OS version matches Windows XP\n");
	}

	if (IsWindows7OrGreater()) {	//current OS version is greater than windows 7? return true when it's true
		printf(" - Current OS version is greater than Windows 7\n");
	}
	else {
		printf(" - Current OS version matches Windows 7\n");
	}

	if (IsWindows8OrGreater()) {	//current OS version is greater than windows 8? return true when it's true
		printf(" - Current OS version is greater than Windows 8\n");
	}
	else {
		printf(" - Current OS version matches Windows 8\n");
	}

	if (IsWindows10OrGreater()) {	//current OS version is greater than windows 10? return true when it's true
		printf(" - Current OS version is greater than Windows 10\n");
	}
	else {
		printf(" - Current OS version matches Windows 10\n");
	}
	printf("------------------------------------------------------------------------------------------------------------\n");

	printf("[*] Getting the Windows version using VerifyVersionInfo with a manifest file\n");
	OSVERSIONINFOEX osvi;	// struct to contain os version to compare with current os
	DWORDLONG dwlConditionMask = 0;	// type of comparison to be used for each osvi member being compared
	int op = VER_GREATER_EQUAL;	//how to compare

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));	// Initialize the OSVERSIONINFOEX structure.

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);	// size
	osvi.dwMajorVersion = 10;	//set dwMajorVersion to compare with current os
	osvi.dwMinorVersion = 0;	//set dwMinorVersion to compare with current os
	osvi.wServicePackMajor = 19043;	//set servicepackmajorversion to compare with current os
	osvi.wServicePackMinor = 1165;	//set servicepackminorversion to compare with current os

	// Initialize the condition mask.

	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);	//	set dwlConditionMask at VER_MAJORVERSION with op(VER_GREATER_EQUAL)
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);	//	set dwlConditionMask at VER_MINORVERSION with op(VER_GREATER_EQUAL)
	VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, op);	//	set dwlConditionMask at VER_SERVICEPACKMAJOR with op(VER_GREATER_EQUAL)
	VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, op);	//	set dwlConditionMask at VER_SERVICEPACKMINOR with op(VER_GREATER_EQUAL)

	int res = VerifyVersionInfo(	//call verifyversioninfo to compare current os with osvi which I set 
		&osvi,
		VER_MAJORVERSION | VER_MINORVERSION |	//comparison items
		VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR,
		dwlConditionMask);
	if (!res) {	//check return value
		DWORD e = ::GetLastError();	// get last error
		if (e == ERROR_OLD_WIN_VERSION) {	//If the current system does not satisfy the requirements, the return value is zero and GetLastError returns ERROR_OLD_WIN_VERSION
			err_print(e);	// call err_print
		}
		else {	//If the function fails, the return value is zero and GetLastError returns an error code other than ERROR_OLD_WIN_VERSION.
			printf(" - %d\n", res);	
		}
	}
	else {	//If the currently running operating system satisfies the specified requirements, the return value is a nonzero value.
		printf(" - %d\n", res);	//	print product type
	}
	
	printf("------------------------------------------------------------------------------------------------------------\n");



	//	 Getting the Windows version using KUSER_SHARED_DATA struct
	printf("[*] Getting the Windows version using KUSER_SHARED_DATA struct\n");
	auto sharedUserData = (BYTE*)0x7FFE0000;	//All apps have this structure at reserved addresses
	printf(" - Version: %d.%d.%d\n",
		*(ULONG*)(sharedUserData + 0x26c), // major version offset
		*(ULONG*)(sharedUserData + 0x270), // minor version offset
		*(ULONG*)(sharedUserData + 0x260)); // build number offset (Windows 10)
	//more https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
	printf("------------------------------------------------------------------------------------------------------------\n");

	return 0;
}
