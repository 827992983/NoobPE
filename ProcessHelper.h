#if !defined(AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_)
#define AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

struct ModuleInfo
{
	TCHAR szExeFile[MAX_PATH];	// ģ���ļ���
	DWORD ImageBase;
	DWORD SizeOfImage;
};

struct ProcessInfo
{
	ModuleInfo MainModuleInfo;	// ��ģ����Ϣ
	DWORD dwPID;				// ����ID
	ModuleInfo *modules;		// ��ģ������
	DWORD dwModules;			// ��ģ������
	
	// 	~ProcessInfo()
	// 	{
	// 		free(modules);
	// 	}
};

DWORD EnumModulesHandle(HANDLE hProcess, HMODULE **lpModule);
DWORD TakeProcessSnapshot(std::vector<ProcessInfo> &processInfos);
BOOL EnableDebugPrivilege();

#endif // !defined(AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_)
