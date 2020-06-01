// NoobPE.cpp : Defines the entry point for the application.
//

/************************************************************************/
/*
ע�����
����Ŀ��ASCII�����¿�������Ȼ�漰�ַ��������ĵط������˺꣬��������ζ�ų���
�ܹ���Unicode�����������ȷ���С���Ϊ����PE������У�������ַ����Ǵ洢���ļ�
�еģ�����󶨵������ OffsetModuleName ����ָ��ģ�������ַ�����ָ�룬�Ҳ�
ȷ����Unicode�Ƿ�����ȷ��ӡ������Ϊ���п��������룩
*/
/************************************************************************/

#include "stdafx.h"

/************************************************************************/
/* ���Ͷ���                                                             */
/************************************************************************/





/************************************************************************/
/* ȫ�ֱ�������                                                         */
/************************************************************************/

HINSTANCE hAppInstance = NULL;
std::vector<ProcessInfo> processInfos; // ��������ʱ��ȡ���̿���

/************************************************************************/
/* ��������                                                             */
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
/* ��ں���                                                             */
/************************************************************************/

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	// ����Ȩ��
	if (!EnableDebugPrivilege())
	{
		MessageBox(NULL, TEXT("��Ȩʧ��"), TEXT("Error"), MB_OK);
	}
	// ��ʼ��ȫ��Ӧ�ó�����
	hAppInstance = hInstance;
	// ���볣��ͨ�ÿؼ�
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

 	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDialogProc);

	return 0;
}

/************************************************************************/
/* ���ڹ���                                                             */
/************************************************************************/

// �����ڹ���
BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);			
			// ����ProcessListView�ķ��
			InitProcessListView(hDlg);
			// ����ModulesListView�ķ��
			InitModulesListView(hDlg);			
			// ���þ���
			CenterWindow(hDlg);
			// ��ȡ���̿���
			TakeProcessSnapshot(processInfos);
			// ��ӡ�����б�
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
					// ����ϵͳ�Ի���ѡȡ�ļ�
					if (GetOpenFileName(&stOpenFile))
					{
						// ���´��ڣ���ʾPE��Ϣ
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

// �����ڡ��Ի��򴰿ڹ���
BOOL CALLBACK AboutDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);						
			// ���þ���
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

// ��PEͷ��Ϣ�Ի��򡱴��ڹ���
BOOL CALLBACK PEInfoDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{	
	// ���浱ǰ�ļ������������� WM_INITDIALOG �¼��и���
	// ���ó� static ��Ϊ���������¼�Ҳ�����ļ���
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// ��ȡ�ļ���			
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);			
			// ���ñ���
			TCHAR szTitle[MAX_PATH];
			memset(szTitle, 0, MAX_PATH * sizeof(TCHAR));
			_stprintf(szTitle, TEXT("[�鿴PE��Ϣ] - %s"), szFile);
			SetWindowText(hDlg, szTitle);
			// ���þ���
			CenterWindow(hDlg);
			// ����PE
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

// �ڱ�Ի���
BOOL CALLBACK SectionDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// ��ȡ�ļ���
			LPCTSTR szFile = (LPCTSTR)lParam;
			//MessageBox(0,szFile, TEXT("DEBUG"),MB_OK);
			// ���þ���
			CenterWindow(hDlg);
			// ��ʼ���б�
			InitSectionListView(hDlg);
			// ��ӡ�ڱ���Ϣ���ڱ�Ի���
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

// Ŀ¼��Ի���
BOOL CALLBACK DirDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// ��ȡ�ļ���
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);			
			// ���þ���
			CenterWindow(hDlg);
			// ��ӡĿ¼����Ϣ			
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

// Ŀ¼����ϸ��Ϣ�Ի���
BOOL CALLBACK DirDetailDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static TCHAR szFile[MAX_PATH];
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// ����ͼ��
			HICON hIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_MAIN));
			// ����ͼ��
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (long)hIcon);
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (long)hIcon);
			// ��ȡ�ļ���
			memset(szFile, 0, sizeof(TCHAR) * MAX_PATH);
			lstrcpy(szFile, (LPCTSTR)lParam);
			// ���þ���
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
/* UI����                                                               */
/************************************************************************/



// ��ʼ�������б����
void InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	// ��ʼ��
	memset(&lv, 0, sizeof(LV_COLUMN));
	// ��ȡ IDC_LIST_PROCESS ���
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
	// ��������ѡ��
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// ��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("����"); // �б���
	lv.cx = 200; // �п�
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	// �ڶ���
	lv.pszText = TEXT("PID");
	lv.cx = 80;
	lv.iSubItem = 1;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	// ������
	lv.pszText = TEXT("�����ַ");
	lv.cx = 80;
	lv.iSubItem = 2;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 2, &lv);
	// ������
	lv.pszText = TEXT("�����С");
	lv.cx = 80;
	lv.iSubItem = 3;
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
	ListView_InsertColumn(hListProcess, 3, &lv);
}

// ��ʼ��ģ���б����
void InitModulesListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListModules;
	// ��ʼ��
	memset(&lv, 0, sizeof(LV_COLUMN));
	// ��ȡ IDC_LIST_PROCESS ���
	hListModules = GetDlgItem(hDlg, IDC_LIST_MODULE);
	// ��������ѡ��
	SendMessage(hListModules, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// ��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("ģ������"); // �б���
	lv.cx = 300; // �п�
	lv.iSubItem = 0;
	SendMessage(hListModules, LVM_INSERTCOLUMN, 0, (DWORD)&lv);	
	// �ڶ���
	lv.pszText = TEXT("�����ַ");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 1, &lv);
	// ������
	lv.pszText = TEXT("�����С");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 2, &lv);
}

// ��ӡ��ö�ٵĽ�����Ϣ
VOID PrintProcess(HWND hListProcess)
{	
	// �ַ���������
	TCHAR lpszBuffer[0x200];	
	
	// LVITEM ��A/W�汾����ߵ�pszTextҲ�������汾������Ҫ�� TEXT ��
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	
	for (int i = 0; i < processInfos.size(); i++)
	{
		vItem.pszText = processInfos[i].MainModuleInfo.szExeFile;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 0; // ��
		ListView_InsertItem(hListProcess, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%d"), processInfos[i].dwPID);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 1; // ��
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
		vItem.iItem = i;	// ��
		vItem.iSubItem = 2; // ��
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
		vItem.iItem = i;	// ��
		vItem.iSubItem = 3; // ��
		ListView_SetItem(hListProcess, &vItem);
	}
}

// ������̣���ӡģ����Ϣ
VOID PrintModules(HWND hListProcess, HWND hListModules, WPARAM wParam, LPARAM lParam)
{
	// ��ȡ��ǰ�У��������� processInfos ���±�
	DWORD dwRowId = -1;
	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		//MessageBox(NULL, TEXT("��ѡ�����"), TEXT("������"), MB_OK);
		return;
	}
	// ��ȡ������Ϣ�ṹ
	ProcessInfo &psi = processInfos[dwRowId];
	// �ַ���������
	TCHAR lpszBuffer[0x200];
	memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
	// ����б�
	ListView_DeleteAllItems(hListModules);
	// ��ӡ��ģ����Ϣ
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	for (size_t i = 0; i < psi.dwModules; i++)
	{
		vItem.pszText = psi.modules[i].szExeFile;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 0; // ��
		ListView_InsertItem(hListModules, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%X"), psi.modules[i].ImageBase);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 1; // ��
		ListView_SetItem(hListModules, &vItem);
		
		memset(lpszBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(lpszBuffer, TEXT("%X"), psi.modules[i].SizeOfImage);
		vItem.pszText = lpszBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 2; // ��
		ListView_SetItem(hListModules, &vItem);
	}
}

// ��ʼ���ڱ��б����
void InitSectionListView(HWND hDlg)
{	
	// ��ȡ IDC_LIST_PROCESS ���
	HWND hListModules = GetDlgItem(hDlg, IDC_LIST_SECTIONS);
	// ��ʼ�� LVITEM
	LV_COLUMN lv;	
	memset(&lv, 0, sizeof(LV_COLUMN));
	// ��������ѡ��
	SendMessage(hListModules, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	// ������Ч��Ϣ
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	// ��һ��
	lv.pszText = TEXT("����"); // �б���
	lv.cx = 80; // �п�
	lv.iSubItem = 0;	
	ListView_InsertColumn(hListModules, 0, &lv);
	// �ڶ���
	lv.pszText = TEXT("VOffset");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 1, &lv);
	// ������
	lv.pszText = TEXT("VSize");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 2, &lv);
	// ������
	lv.pszText = TEXT("ROffset"); // �б���
	lv.cx = 80; // �п�
	lv.iSubItem = 0;	
	ListView_InsertColumn(hListModules, 3, &lv);
	// ������
	lv.pszText = TEXT("RSize");
	lv.cx = 80;
	lv.iSubItem = 1;	
	ListView_InsertColumn(hListModules, 4, &lv);
	// ������
	lv.pszText = TEXT("��־");
	lv.cx = 80;
	lv.iSubItem = 2;	
	ListView_InsertColumn(hListModules, 5, &lv);
}

/************************************************************************/
/* ���ܺ���                                                             */
/************************************************************************/



