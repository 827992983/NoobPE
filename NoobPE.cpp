// NoobPE.cpp : Defines the entry point for the application.
//

/************************************************************************/
/*
注意事项：
本项目在ASCII编码下开发，虽然涉及字符串操作的地方都用了宏，但并不意味着程序
能够在Unicode编码情况下正确运行。因为解析PE表过程中，有许多字符串是存储在文件
中的，例如绑定导入表中 OffsetModuleName 就是指向模块名称字符串的指针，我不
确定用Unicode是否能正确打印（我认为极有可能是乱码）
*/
/************************************************************************/

#include "stdafx.h"

/************************************************************************/
/* 类型定义                                                             */
/************************************************************************/





/************************************************************************/
/* 全局变量声明                                                         */
/************************************************************************/

HINSTANCE hAppInstance = NULL;
std::vector<ProcessInfo> processInfos; // 程序启动时获取进程快照

/************************************************************************/
/* 函数声明                                                             */
/************************************************************************/

BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

void InitProcessListView(HWND hDlg);
void InitModulesListView(HWND hDlg);
VOID PrintProcess(HWND hListProcess);
VOID PrintModules(HWND hListProcess, HWND hListModules, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK AboutDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PEInfoDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK SectionDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK DirDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK DirDetailDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void InitSectionListView(HWND hDlg);


/************************************************************************/
/* 入口函数                                                             */
/************************************************************************/

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	// 起升权限
	if (!EnableDebugPrivilege())
	{
		MessageBox(NULL, TEXT("提权失败"), TEXT("Error"), MB_OK);
	}
	// 初始化全局应用程序句柄
	hAppInstance = hInstance;
	// 导入常用通用控件
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

 	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDialogProc);

	return 0;
}

/************************************************************************/
/* 窗口过程                                                             */
/************************************************************************/

// 主窗口过程
BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);			
			// 设置ProcessListView的风格
			InitProcessListView(hDlg);
			// 设置ModulesListView的风格
			InitModulesListView(hDlg);			
			// 设置居中
			CenterWindow(hDlg);
			// 获取进程快照
			TakeProcessSnapshot(processInfos);
			// 打印进程列表
			PrintProcess(GetDlgItem(hDlg, IDC_LIST_PROCESS));			
			
			return TRUE;
		}
	case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*)lParam;
			if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
			{
				PrintModules(GetDlgItem(hDlg,IDC_LIST_PROCESS), GetDlgItem(hDlg,IDC_LIST_MODULE), wParam, lParam);
			}
			return TRUE;
		}
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDC_BUTTON_OPEN:
				{					
					LPCTSTR szPeFileExt = TEXT("PE File\0*.EXE;*.DLL;*.SCR;*.DRV;*.SYS\0");
					TCHAR szFileName[MAX_PATH];
					OPENFILENAME stOpenFile;
					memset(szFileName, 0, MAX_PATH * sizeof(TCHAR));
					memset(&stOpenFile, 0, sizeof(OPENFILENAME));
					stOpenFile.lStructSize = sizeof(OPENFILENAME);
					stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
					stOpenFile.hwndOwner = hDlg;
					stOpenFile.lpstrFilter = szPeFileExt;
					stOpenFile.lpstrFile = szFileName;
					stOpenFile.nMaxFile = MAX_PATH;
					// 调用系统对话框选取文件
					if (GetOpenFileName(&stOpenFile))
					{
						// 打开新窗口，显示PE信息
						DialogBoxParam(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_PEINFO), \
							hDlg, PEInfoDialogProc, (LPARAM)&szFileName);
					}					
					return TRUE;
				}
			case IDC_BUTTON_ABOUT:
				{					
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_ABOUT), hDlg, AboutDialogProc);
					return TRUE;
				}
			case IDC_BUTTON_QUIT:
				{					
					EndDialog(hDlg, 0);
					return TRUE;
				}
			}
			return TRUE;
		}
	case WM_CLOSE:
		{
			EndDialog(hDlg, 0);
			return TRUE;	
		}
		
	}
	return FALSE;
}

// “关于”对话框窗口过程
BOOL CALLBACK AboutDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);						
			// 设置居中
			CenterWindow(hDlg);
			return TRUE;
		}
	case WM_CLOSE:
		{
			EndDialog(hDlg, 0);
			return TRUE;	
		}
	}
	return FALSE;
}

// “PE头信息对话框”窗口过程
BOOL CALLBACK PEInfoDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{	
	// 保存当前文件名，该数组在 WM_INITDIALOG 事件中更新
	// 设置成 static 是为了让其他事件也能用文件名
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// 获取文件名			
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);			
			// 设置标题
			TCHAR szTitle[MAX_PATH];
			memset(szTitle, 0, MAX_PATH * sizeof(TCHAR));
			_stprintf(szTitle, TEXT("[查看PE信息] - %s"), szFile);
			SetWindowText(hDlg, szTitle);
			// 设置居中
			CenterWindow(hDlg);
			// 解析PE
			PrintPEInfo(hDlg, szFile);
			return TRUE;
		}
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDC_BUTTON_PEINFO_SECTION:
				{					
					DialogBoxParam(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_SECTION), hDlg, SectionDialogProc, (LPARAM)&szFile);
					return TRUE;
				}
			case IDC_BUTTON_PEINFO_DIR:
				{					
					DialogBoxParam(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR), hDlg, DirDialogProc, (LPARAM)&szFile);
					return TRUE;
				}
			case IDC_BUTTON_PEINFO_QUIT:
				{
					EndDialog(hDlg, 0);
					return TRUE;
				}
			}
			return TRUE;
		}
	case WM_CLOSE:
		{
			{
				EndDialog(hDlg, 0);
				return TRUE;	
			}
		}
	}
	return FALSE;
}

// 节表对话框
BOOL CALLBACK SectionDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// 获取文件名
			LPCTSTR szFile = (LPCTSTR)lParam;
			//MessageBox(0,szFile, TEXT("DEBUG"),MB_OK);
			// 设置居中
			CenterWindow(hDlg);
			// 初始化列表
			InitSectionListView(hDlg);
			// 打印节表信息到节表对话框
			PrintSectionInfo(hDlg, szFile);
			return TRUE;
		}	
	case WM_CLOSE:
		{
			{
				EndDialog(hDlg, 0);
				return TRUE;	
			}
		}
	}
	return FALSE;
}

// 目录项对话框
BOOL CALLBACK DirDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// 获取文件名
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);			
			// 设置居中
			CenterWindow(hDlg);
			// 打印目录项信息			
			PrintDirInfo(hDlg, szFile);
			return TRUE;
		}
	case WM_COMMAND:
		{			
			switch(LOWORD(wParam))
			{
			case IDC_BUTTON_DIR_EXPORT:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_EXPORT_TABLE, 0, 0);
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_IMPORT:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_IMPORT_TABLE, 0, 0);
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_RES:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_RES_TABLE, 0, 0);						
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_RELOC:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_RELOC_TABLE, 0, 0);						
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_BOUNDIMPORT:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_BOUND_IMPORT_TABLE, 0, 0);						
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_IAT:
				{
					HWND hDetailDlg = CreateDialogParam(hAppInstance, \
						MAKEINTRESOURCE(IDD_DIALOG_DIRDETAIL), hDlg, DirDetailDialogProc, (LPARAM)&szFile);					
					if (hDetailDlg != NULL)
					{
						SendMessage(hDetailDlg, WM_PRINT_IAT_TABLE, 0, 0);						
					}
					return TRUE;
				}
			case IDC_BUTTON_DIR_QUIT:
				{
					EndDialog(hDlg, 0);
					return TRUE;
				}
			}
			return TRUE;
		}
	case WM_CLOSE:
		{
			{
				EndDialog(hDlg, 0);
				return TRUE;	
			}
		}
	}
	return FALSE;
}

// 目录项详细信息对话框
BOOL CALLBACK DirDetailDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// 加载图标
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// 设置图标
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// 获取文件名
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);
			// 设置居中
			CenterWindow(hDlg);			
			return TRUE;
		}
	case WM_PRINT_EXPORT_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintExportTable(hEdit, szFile);
			return TRUE;
		}
	case WM_PRINT_IMPORT_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintImportTable(hEdit, szFile);
			return TRUE;
		}
	case WM_PRINT_RES_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintResourceTable(hEdit, szFile);			
			return TRUE;
		}
	case WM_PRINT_RELOC_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintRelocationTable(hEdit, szFile);			
			return TRUE;
		}
	case WM_PRINT_BOUND_IMPORT_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintBoundImportTable(hEdit, szFile);
			return TRUE;
		}
	case WM_PRINT_IAT_TABLE:
		{
			HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_DIRDETAIL);
			ShowWindow(hDlg, SW_SHOW);
			PrintIATTable(hEdit, szFile);
			return TRUE;
		}
	case WM_CLOSE:
		{
			{
				//EndDialog(hDlg, 0);
				DestroyWindow(hDlg);
				return TRUE;	
			}
		}
	}
	return FALSE;
}


/************************************************************************/
/* UI设置                                                               */
/************************************************************************/



// 初始化进程列表标题
void InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	// 初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	// 获取 IDC_LIST_PROCESS 句柄
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
	// 设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("进程"); // 列标题
	lv.cx = 200; // 列宽
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	// 第二列
	lv.pszText = TEXT("PID");
	lv.cx = 80;
	lv.iSubItem = 1;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	// 第三列
	lv.pszText = TEXT("镜像基址");
	lv.cx = 80;
	lv.iSubItem = 2;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 2, &lv);
	// 第四列
	lv.pszText = TEXT("镜像大小");
	lv.cx = 80;
	lv.iSubItem = 3;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 3, &lv);
}

// 初始化模块列表标题
void InitModulesListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListModules;
	// 初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	// 获取 IDC_LIST_PROCESS 句柄
	hListModules = GetDlgItem(hDlg, IDC_LIST_MODULE);
	// 设置整行选中
	SendMessage(hListModules, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("模块名称"); // 列标题
	lv.cx = 300; // 列宽
	lv.iSubItem = 0;
	SendMessage(hListModules, LVM_INSERTCOLUMN, 0, (DWORD)&lv);	
	// 第二列
	lv.pszText = TEXT("镜像基址");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 1, &lv);
	// 第三列
	lv.pszText = TEXT("镜像大小");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 2, &lv);
}

// 打印已枚举的进程信息
VOID PrintProcess(HWND hListProcess)
{	
	// 字符串缓冲区
	TCHAR lpszBuffer[0x200];	
	
	// LVITEM 有A/W版本，里边的pszText也有两个版本，所以要用 TEXT 宏
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	
	for (int i = 0; i < processInfos.size(); i++)
	{
		vItem.pszText = processInfos[i].MainModuleInfo.szExeFile;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 0; // 列
		ListView_InsertItem(hListProcess, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%d"), processInfos[i].dwPID);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 1; // 列
		ListView_SetItem(hListProcess, &vItem);
		
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		if (processInfos[i].dwModules == 0)
		{
			_stprintf(lpszBuffer, TEXT("0"));
		}
		else
		{
			_stprintf(lpszBuffer, TEXT("%X"), processInfos[i].modules->ImageBase);
		}		
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 2; // 列
		ListView_SetItem(hListProcess, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		if (processInfos[i].dwModules == 0)
		{
			_stprintf(lpszBuffer, TEXT("0"));
		}
		else
		{
			_stprintf(lpszBuffer, TEXT("%X"), processInfos[i].modules->SizeOfImage);
		}
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 3; // 列
		ListView_SetItem(hListProcess, &vItem);
	}
}

// 点击进程，打印模块信息
VOID PrintModules(HWND hListProcess, HWND hListModules, WPARAM wParam, LPARAM lParam)
{
	// 获取当前行，行数就是 processInfos 的下标
	DWORD dwRowId = -1;
	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		//MessageBox(NULL, TEXT("请选择进程"), TEXT("出错啦"), MB_OK);
		return;
	}
	// 获取进程信息结构
	ProcessInfo &psi = processInfos[dwRowId];
	// 字符串缓冲区
	TCHAR lpszBuffer[0x200];
	memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
	// 清空列表
	ListView_DeleteAllItems(hListModules);
	// 打印子模块信息
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	for (size_t i = 0; i < psi.dwModules; i++)
	{
		vItem.pszText = psi.modules[i].szExeFile;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 0; // 列
		ListView_InsertItem(hListModules, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%X"), psi.modules[i].ImageBase);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 1; // 列
		ListView_SetItem(hListModules, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%X"), psi.modules[i].SizeOfImage);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 2; // 列
		ListView_SetItem(hListModules, &vItem);
	}
}

// 初始化节表列表标题
void InitSectionListView(HWND hDlg)
{	
	// 获取 IDC_LIST_PROCESS 句柄
	HWND hListModules = GetDlgItem(hDlg, IDC_LIST_SECTIONS);
	// 初始化 LVITEM
	LV_COLUMN lv;	
	memset(&lv, 0, sizeof(LV_COLUMN));
	// 设置整行选中
	SendMessage(hListModules, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// 设置有效信息
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	// 第一列
	lv.pszText = TEXT("名称"); // 列标题
	lv.cx = 80; // 列宽
	lv.iSubItem = 0;	
	ListView_InsertColumn(hListModules, 0, &lv);
	// 第二列
	lv.pszText = TEXT("VOffset");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 1, &lv);
	// 第三列
	lv.pszText = TEXT("VSize");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 2, &lv);
	// 第四列
	lv.pszText = TEXT("ROffset"); // 列标题
	lv.cx = 80; // 列宽
	lv.iSubItem = 0;	
	ListView_InsertColumn(hListModules, 3, &lv);
	// 第五列
	lv.pszText = TEXT("RSize");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 4, &lv);
	// 第六列
	lv.pszText = TEXT("标志");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 5, &lv);
}

/************************************************************************/
/* 功能函数                                                             */
/************************************************************************/



