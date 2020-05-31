// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
#define AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include "resource.h"
// 导入通用控件DLL
#include <COMMCTRL.H>
#pragma comment(lib, "comctl32.lib")

#include <stdio.h>
#include <MALLOC.H>
#include <TLHELP32.H>
#include <psapi.h>
#pragma comment(lib,"psapi.lib")

#include <vector>
#include "ProcessHelper.h"

#include <STDLIB.H>
#include <TCHAR.H>

// 导入通用对话框
#include <COMMDLG.H>
#pragma comment(lib, "comdlg32.lib")

#include "PE.h"
#include "UIHelper.h"
#include "UserMessage.h"

// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
