#include "stdafx.h"
#include "UIHelper.h"

// ���д���
void CenterWindow(HWND hWnd)
{
    int scrWidth, scrHeight;
    RECT rect;
    //�����Ļ�ߴ�
    scrWidth = GetSystemMetrics(SM_CXSCREEN);
    scrHeight = GetSystemMetrics(SM_CYSCREEN);
    //ȡ�ô��ڳߴ�
    GetWindowRect(hWnd, &rect);
    //��������rect���ֵ  
    long width = rect.right - rect.left;
    long height = rect.bottom - rect.top;
    rect.left = (scrWidth - width) / 2;
    rect.top = (scrHeight - height) / 2;
	
    //�ƶ����ڵ�ָ����λ��
    SetWindowPos(hWnd, HWND_TOP, rect.left, rect.top, width, height, SWP_NOSIZE | SWP_NOZORDER);
}

// �� Edit �ؼ�׷���ַ���
void AddText(HWND hEditControl, LPCTSTR szNewStr)
{
	// ��ȡ��ǰ�ؼ��ڵ��ַ���
    int nTextLen = GetWindowTextLength(hEditControl);
	// �����ַ��������ڴ棬����ʼ��
    LPTSTR szResult = (LPTSTR)malloc((nTextLen + lstrlen(szNewStr) + 1) * sizeof(TCHAR));
	if (szResult == NULL) return;
	memset(szResult, 0, (nTextLen + lstrlen(szNewStr) + 1) * sizeof(TCHAR));
    // ���ַ�Ϊ��λ�����ı�������
    GetWindowText(hEditControl, szResult, nTextLen + 1); // ������������ʾ����ַ���������NULL
	lstrcat(&szResult[nTextLen], szNewStr);    
    SetWindowText(hEditControl, szResult);
    free(szResult);
	UpdateWindow(hEditControl);
    return;
}

// �� Edit �ؼ�׷���ַ�����Unicode�汾
// ��Դ��� NameOffset ָ���ȫ�� Unicode �ַ��������������ASCII���룬Ҫ��ȷ��ӡUnicode�����ʹ�øÿ��ַ��汾
void AddTextW(HWND hEditControl, LPCWSTR szNewStr)
{
	// ��ȡ��ǰ�ؼ��ڵ��ַ���
    int nTextLen = GetWindowTextLengthW(hEditControl);
	// �����ַ��������ڴ棬����ʼ��
    LPWSTR szResult = (LPWSTR)malloc((nTextLen + wcslen(szNewStr) + 1) * sizeof(WCHAR));
	if (szResult == NULL) return;
	memset(szResult, 0, (nTextLen + wcslen(szNewStr) + 1) * sizeof(WCHAR));
    // ���ַ�Ϊ��λ�����ı�������
    GetWindowTextW(hEditControl, szResult, nTextLen + 1); // ������������ʾ����ַ���������NULL
	wcscat(&szResult[nTextLen], szNewStr);
    SetWindowTextW(hEditControl, szResult);
    free(szResult);
	UpdateWindow(hEditControl);
    return;
}