#include "stdafx.h"
#include "UIHelper.h"

// 居中窗口
void CenterWindow(HWND hWnd)
{
    int scrWidth, scrHeight;
    RECT rect;
    //获得屏幕尺寸
    scrWidth = GetSystemMetrics(SM_CXSCREEN);
    scrHeight = GetSystemMetrics(SM_CYSCREEN);
    //取得窗口尺寸
    GetWindowRect(hWnd, &rect);
    //重新设置rect里的值  
    long width = rect.right - rect.left;
    long height = rect.bottom - rect.top;
    rect.left = (scrWidth - width) / 2;
    rect.top = (scrHeight - height) / 2;
	
    //移动窗口到指定的位置
    SetWindowPos(hWnd, HWND_TOP, rect.left, rect.top, width, height, SWP_NOSIZE | SWP_NOZORDER);
}

// 向 Edit 控件追加字符串
void AddText(HWND hEditControl, LPCTSTR szNewStr)
{
	// 获取当前控件内的字符数
    int nTextLen = GetWindowTextLength(hEditControl);
	// 给新字符串分配内存，并初始化
    LPTSTR szResult = (LPTSTR)malloc((nTextLen + lstrlen(szNewStr) + 1) * sizeof(TCHAR));
	if (szResult == NULL) return;
	memset(szResult, 0, (nTextLen + lstrlen(szNewStr) + 1) * sizeof(TCHAR));
    // 以字符为单位复制文本框内容
    GetWindowText(hEditControl, szResult, nTextLen + 1); // 第三个参数表示最大字符数，包括NULL
	lstrcat(&szResult[nTextLen], szNewStr);    
    SetWindowText(hEditControl, szResult);
    free(szResult);
	UpdateWindow(hEditControl);
    return;
}

// 向 Edit 控件追加字符串，Unicode版本
// 资源表的 NameOffset 指向的全是 Unicode 字符串，如果工程以ASCII编译，要正确打印Unicode则必须使用该宽字符版本
void AddTextW(HWND hEditControl, LPCWSTR szNewStr)
{
	// 获取当前控件内的字符数
    int nTextLen = GetWindowTextLengthW(hEditControl);
	// 给新字符串分配内存，并初始化
    LPWSTR szResult = (LPWSTR)malloc((nTextLen + wcslen(szNewStr) + 1) * sizeof(WCHAR));
	if (szResult == NULL) return;
	memset(szResult, 0, (nTextLen + wcslen(szNewStr) + 1) * sizeof(WCHAR));
    // 以字符为单位复制文本框内容
    GetWindowTextW(hEditControl, szResult, nTextLen + 1); // 第三个参数表示最大字符数，包括NULL
	wcscat(&szResult[nTextLen], szNewStr);
    SetWindowTextW(hEditControl, szResult);
    free(szResult);
	UpdateWindow(hEditControl);
    return;
}