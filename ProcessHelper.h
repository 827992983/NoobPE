#if !defined(AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_)
#define AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

struct ModuleInfo
{
	TCHAR szExeFile[MAX_PATH];	// 模块文件名
	DWORD ImageBase;
	DWORD SizeOfImage;
};

struct ProcessInfo
{
	ModuleInfo MainModuleInfo;	// 主模块信息
	DWORD dwPID;				// 进程ID
	ModuleInfo *modules;		// 子模块数组
	DWORD dwModules;			// 子模块数量
	
	// 	~ProcessInfo()
	// 	{
	// 		free(modules);
	// 	}
};

DWORD EnumModulesHandle(HANDLE hProcess, HMODULE **lpModule);
DWORD TakeProcessSnapshot(std::vector<ProcessInfo> &processInfos);
BOOL EnableDebugPrivilege();

#endif // !defined(AFX_PROCESSHELPER_H__B0051A71_F21E_4F78_AFD6_466C2CC964A5__INCLUDED_)
