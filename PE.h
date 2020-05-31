#if !defined(AFX_PE_H__6E946D22_DE4A_48E9_B7CC_9F6E3DD72372__INCLUDED_)
#define AFX_PE_H__6E946D22_DE4A_48E9_B7CC_9F6E3DD72372__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

BOOL IsPEFile(LPVOID pFileBuffer, DWORD dwSize);
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva);
BOOL PrintPEInfo(HWND hDlg, LPCTSTR szFile);
DWORD ReadPEFile(LPCTSTR lpszFile, LPVOID *pFileBuffer);
BOOL PrintSectionInfo(HWND hDlg, LPCTSTR szFile);
BOOL PrintDirInfo(HWND hDlg, LPCTSTR szFile);
VOID PrintExportTable(HWND hEdit, LPCTSTR szFile);
VOID PrintImportTable(HWND hEdit, LPCTSTR szFile);
VOID PrintResourceTable(HWND hEdit, LPCTSTR szFile);
VOID PrintRelocationTable(HWND hEdit, LPCTSTR szFile);
VOID PrintBoundImportTable(HWND hEdit, LPCTSTR szFile);
VOID PrintIATTable(HWND hEdit, LPCTSTR szFile);





#endif // !defined(AFX_PE_H__6E946D22_DE4A_48E9_B7CC_9F6E3DD72372__INCLUDED_)
