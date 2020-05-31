#include "stdafx.h"
#include "ProcessHelper.h"

// ö�ٽ��̵�ַ�ռ��ڵ�ģ�������������鳤��
DWORD EnumModulesHandle(HANDLE hProcess, HMODULE **lpModule)
{
	DWORD cbBytesNeeded = 0;
	// ��ע��EnumProcessModules �����޷�ö��64λ���̵�ģ�飬���ǳ�����64λ����
	EnumProcessModules(hProcess, NULL, 0, &cbBytesNeeded); // ���������С
	*lpModule = (HMODULE *)malloc(cbBytesNeeded + 0x1000);
	EnumProcessModules(hProcess, *lpModule, cbBytesNeeded + 0x1000, &cbBytesNeeded); // ö��ģ����
	return cbBytesNeeded / sizeof(HMODULE);
}

// ��ȡ��ǰ���н��̵���Ϣ
DWORD TakeProcessSnapshot(std::vector<ProcessInfo> &processInfos)
{
	processInfos.clear();
	// ��ȡ���̿��գ��õ���ǰ���н��̵�PID
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("��ȡ���̿���ʧ��"), TEXT("Error"), MB_OK);
		return -1;
	}	
	// ��������
	BOOL bNext = Process32First(hProcessSnapshot, &pe32);
	while (bNext)
	{
		ProcessInfo psi;
		memset(&psi, 0, sizeof(ProcessInfo));
		lstrcpy(psi.MainModuleInfo.szExeFile, pe32.szExeFile);
		psi.dwPID = pe32.th32ProcessID;		
		
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, psi.dwPID);		
		if (hProcess != NULL)
		{
			HMODULE *lpModuleHandle = NULL;
			psi.dwModules = EnumModulesHandle(hProcess, &lpModuleHandle);
			psi.modules = (ModuleInfo*)malloc(psi.dwModules * sizeof(ModuleInfo));
			MODULEINFO moduleInfo;
			for (size_t i = 0; i < psi.dwModules; i++)
			{
				GetModuleInformation(hProcess, lpModuleHandle[i], &moduleInfo, sizeof(MODULEINFO));
				//printf("\t%x\t%x\n", lpModuleHandle[i], moduleInfo.SizeOfImage);
				GetModuleFileNameEx(hProcess, lpModuleHandle[i], (psi.modules)[i].szExeFile, MAX_PATH);
				(psi.modules)[i].ImageBase = (DWORD)(lpModuleHandle[i]);
				(psi.modules)[i].SizeOfImage = moduleInfo.SizeOfImage;
			}
			free(lpModuleHandle);
		}
		processInfos.push_back(psi);
		bNext = Process32Next(hProcessSnapshot, &pe32);
	}
	return 0;
}

// ��Ȩ����������ΪDEBUGȨ��
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk=FALSE;
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount=1;
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);
		
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
		
		fOk=(GetLastError()==ERROR_SUCCESS);
		CloseHandle(hToken);
	}
    return fOk;
}
