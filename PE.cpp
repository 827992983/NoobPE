#include "stdafx.h"
#include "PE.h"

// ��֤�Ƿ�PE�ļ�
BOOL IsPEFile(LPVOID pFileBuffer, DWORD dwSize)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	if (*((PWORD)pDosHeader) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return FALSE;
	}
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE���\n");
		return FALSE;
	}
	
	return TRUE;
}

// RVA ת FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	// RVA���ļ�ͷ�л����ļ�����==�ڴ����ʱ��RVA==FOA  ����һ���ǶԵģ��ڶ����Ǵ��
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}
	
	// �����ڱ�ȷ��ƫ��������һ����	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && \
			dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("�Ҳ���RVA %x ��Ӧ�� FOA��ת��ʧ��\n", dwRva);
	return 0;
}

// ��ȡPE�ļ����ڴ��У����ض�ȡ���ֽ�������ȡʧ�ܷ���0
DWORD ReadPEFile(LPCTSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = _tfopen(lpszFile, TEXT("rb"));
	if (pFile == NULL) 
	{
		printf("���ļ�ʧ��\n");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{		
		fclose(pFile);
		return 0;
	}	
	DWORD dwRead = fread(*pFileBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	if (dwRead != dwFileSize)
	{		
		return 0;
	}
	if (!IsPEFile(*pFileBuffer, dwRead))
	{		
		return 0;
	}
	return dwRead;
}

// �����ļ���������PE�ļ�������Ϣ��ʾ�� PEInfoDialog
BOOL PrintPEInfo(HWND hDlg, LPCTSTR szFile)
{
	// ����PE�ļ�
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		MessageBox(hDlg, TEXT("�ļ�������"), TEXT("Error"), MB_OK);
		return FALSE;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);	

	// ��ȡ�ı�����
	HWND hEditEntryPoint = GetDlgItem(hDlg, IDC_EDIT_PEINFO_ENTRYPOINT);
	HWND hEditImageBase = GetDlgItem(hDlg, IDC_EDIT_PEINFO_IMAGEBASE);
	HWND hEditSizeOfImage = GetDlgItem(hDlg, IDC_EDIT_PEINFO_SIZEOFIMAGE);
	HWND hEditBaseOfCode = GetDlgItem(hDlg, IDC_EDIT_PEINFO_BASEOFCODE);
	HWND hEditBaseOfData = GetDlgItem(hDlg, IDC_EDIT_PEINFO_BASEOFDATA);
	HWND hEditSectionAlign = GetDlgItem(hDlg, IDC_EDIT_PEINFO_SECTIONALIGN);
	HWND hEditFileAlign = GetDlgItem(hDlg, IDC_EDIT_PEINFO_FILEALIGN);
	HWND hEditMagic = GetDlgItem(hDlg, IDC_EDIT_PEINFO_MAGIC);
	HWND hEditSubSystem = GetDlgItem(hDlg, IDC_EDIT_PEINFO_SUBSYS);
	HWND hEditNumberOfSections = GetDlgItem(hDlg, IDC_EDIT_PEINFO_NUMBEROFSECTION);
	HWND hEditTimeStamp = GetDlgItem(hDlg, IDC_EDIT_PEINFO_TIMESTAMP);
	HWND hEditSizeOfHeader = GetDlgItem(hDlg, IDC_EDIT_PEINFO_SIZEOFHEADER);
	HWND hEditCharacteristic = GetDlgItem(hDlg, IDC_EDIT_PEINFO_CHARC);
	HWND hEditCheckSum = GetDlgItem(hDlg, IDC_EDIT_PEINFO_CHECKSUM);
	HWND hEditSizeOfOptionHeader = GetDlgItem(hDlg, IDC_EDIT_PEINFO_SIZEOFOPHEADER);
	HWND hEditNumberOfRvaAndSizes = GetDlgItem(hDlg, IDC_EDIT_PEINFO_NUMBEROFRVAANDSIZES);

	// �����ַ�������
	const int cbBuffer = 0x100;
	TCHAR szBuffer[cbBuffer];

	// ���
	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->AddressOfEntryPoint);
	SetWindowText(hEditEntryPoint, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->ImageBase);
	SetWindowText(hEditImageBase, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->SizeOfImage);
	SetWindowText(hEditSizeOfImage, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->BaseOfCode);
	SetWindowText(hEditBaseOfCode, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->BaseOfData);
	SetWindowText(hEditBaseOfData, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->SectionAlignment);
	SetWindowText(hEditSectionAlign, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->FileAlignment);
	SetWindowText(hEditFileAlign, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->Magic);
	SetWindowText(hEditMagic, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->Subsystem);
	SetWindowText(hEditSubSystem, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pPEHeader->NumberOfSections);
	SetWindowText(hEditNumberOfSections, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pPEHeader->TimeDateStamp);
	SetWindowText(hEditTimeStamp, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->SizeOfHeaders);
	SetWindowText(hEditSizeOfHeader, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pPEHeader->Characteristics);
	SetWindowText(hEditCharacteristic, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->CheckSum);
	SetWindowText(hEditCheckSum, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pPEHeader->SizeOfOptionalHeader);
	SetWindowText(hEditSizeOfOptionHeader, szBuffer);

	memset(szBuffer, 0, cbBuffer * sizeof(TCHAR));
	_stprintf(szBuffer, TEXT("%X"), pOptionHeader->NumberOfRvaAndSizes);
	SetWindowText(hEditNumberOfRvaAndSizes, szBuffer);

	free(pFileBuffer);
	return TRUE;
}

// �����ļ���������PE�ļ������ڱ���Ϣ��ʾ�� PESectionDialog
BOOL PrintSectionInfo(HWND hDlg, LPCTSTR szFile)
{
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTIONS);
	TCHAR szBuffer[0x200];
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	
	// ����PE�ļ�
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		return FALSE;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	// �����ڱ�
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		// ������
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		memcpy(szBuffer, pSectionHeader[i].Name, 8);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 0; // ��
		ListView_InsertItem(hListSection, &vItem);
		// �ڴ�ƫ��
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].VirtualAddress);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 1; // ��
		ListView_SetItem(hListSection, &vItem);
		// �ڴ��С
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].Misc.VirtualSize);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 2; // ��
		ListView_SetItem(hListSection, &vItem);
		// �ļ�ƫ��
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].PointerToRawData);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 3; // ��
		ListView_SetItem(hListSection, &vItem);
		// �ļ���С
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].SizeOfRawData);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 4; // ��
		ListView_SetItem(hListSection, &vItem);
		// ����
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].Characteristics);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// ��
		vItem.iSubItem = 5; // ��
		ListView_SetItem(hListSection, &vItem);
	}	
	return TRUE;
}

// ��ӡĿ¼����Ϣ��Ŀ¼��Ի���
BOOL PrintDirInfo(HWND hDlg, LPCTSTR szFile)
{
	// ��ʼ���ı�����
	HWND aHwnd[32] = {0};

	aHwnd[0] = GetDlgItem(hDlg, IDC_EDIT_DIR_EXPORT_RVA);
	aHwnd[1] = GetDlgItem(hDlg, IDC_EDIT_DIR_IMPORT_RVA);
	aHwnd[2] = GetDlgItem(hDlg, IDC_EDIT_DIR_RES_RVA);
	aHwnd[3] = GetDlgItem(hDlg, IDC_EDIT_DIR_EXCEPTION_RVA);
	aHwnd[4] = GetDlgItem(hDlg, IDC_EDIT_DIR_SECURITY_RVA);
	aHwnd[5] = GetDlgItem(hDlg, IDC_EDIT_DIR_BASERELOC_RVA);
	aHwnd[6] = GetDlgItem(hDlg, IDC_EDIT_DIR_DEBUG_RVA);
	aHwnd[7] = GetDlgItem(hDlg, IDC_EDIT_DIR_COPYRIGHT_RVA);
	aHwnd[8] = GetDlgItem(hDlg, IDC_EDIT_DIR_GLOBALPTR_RVA);
	aHwnd[9] = GetDlgItem(hDlg, IDC_EDIT_DIR_TLS_RVA);
	aHwnd[10] = GetDlgItem(hDlg, IDC_EDIT_DIR_LOADCONFIG_RVA);
	aHwnd[11] = GetDlgItem(hDlg, IDC_EDIT_DIR_BOUNDIMPORT_RVA);
	aHwnd[12] = GetDlgItem(hDlg, IDC_EDIT_DIR_IAT_RVA);
	aHwnd[13] = GetDlgItem(hDlg, IDC_EDIT_DIR_DELAYIMPORT_RVA);
	aHwnd[14] = GetDlgItem(hDlg, IDC_EDIT_DIR_COM_RVA);
	aHwnd[15] = GetDlgItem(hDlg, IDC_EDIT_DIR_RETAIN_RVA);
	
	aHwnd[16 + 0] = GetDlgItem(hDlg, IDC_EDIT_DIR_EXPORT_SIZE);
	aHwnd[16 + 1] = GetDlgItem(hDlg, IDC_EDIT_DIR_IMPORT_SIZE);
	aHwnd[16 + 2] = GetDlgItem(hDlg, IDC_EDIT_DIR_RES_SIZE);
	aHwnd[16 + 3] = GetDlgItem(hDlg, IDC_EDIT_DIR_EXCEPTION_SIZE);
	aHwnd[16 + 4] = GetDlgItem(hDlg, IDC_EDIT_DIR_SECURITY_SIZE);
	aHwnd[16 + 5] = GetDlgItem(hDlg, IDC_EDIT_DIR_BASERELOC_SIZE);
	aHwnd[16 + 6] = GetDlgItem(hDlg, IDC_EDIT_DIR_DEBUG_SIZE);
	aHwnd[16 + 7] = GetDlgItem(hDlg, IDC_EDIT_DIR_COPYRIGHT_SIZE);
	aHwnd[16 + 8] = GetDlgItem(hDlg, IDC_EDIT_DIR_GLOBALPTR_SIZE);
	aHwnd[16 + 9] = GetDlgItem(hDlg, IDC_EDIT_DIR_TLS_SIZE);
	aHwnd[16 + 10] = GetDlgItem(hDlg, IDC_EDIT_DIR_LOADCONFIG_SIZE);
	aHwnd[16 + 11] = GetDlgItem(hDlg, IDC_EDIT_DIR_BOUNDIMPORT_SIZE);
	aHwnd[16 + 12] = GetDlgItem(hDlg, IDC_EDIT_DIR_IAT_SIZE);
	aHwnd[16 + 13] = GetDlgItem(hDlg, IDC_EDIT_DIR_DELAYIMPORT_SIZE);
	aHwnd[16 + 14] = GetDlgItem(hDlg, IDC_EDIT_DIR_COM_SIZE);
	aHwnd[16 + 15] = GetDlgItem(hDlg, IDC_EDIT_DIR_RETAIN_SIZE);

	// ��ӡ����Ŀ¼
	TCHAR szBuffer[0x200];
	LPVOID pFileBuffer = NULL;
	if (ReadPEFile(szFile, &pFileBuffer) == 0)
	{
		MessageBox(hDlg, TEXT("�ļ�������"), TEXT("Error"), MB_OK);
		return FALSE;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	for (int i = 0; i < 16; i++)
	{
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), (pOptionHeader->DataDirectory)[i].VirtualAddress);
		SetWindowText(aHwnd[i], szBuffer);

		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), (pOptionHeader->DataDirectory)[i].Size);
		SetWindowText(aHwnd[i + 16], szBuffer);
		
	}
	free(pFileBuffer);
	return TRUE;
}

// ��ӡ������
VOID PrintExportTable(HWND hEdit, LPCTSTR szFile)
{
	// ����PE�ļ�
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{		
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (pOptionHeader->DataDirectory[0].VirtualAddress == NULL)
	{
		return;
	}
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = \
		(PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[0].VirtualAddress));	
	TCHAR szBuffer[0x200];
	memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
	// ��ӡ
	_stprintf(szBuffer, TEXT("AddressOfFunctions: %X\r\n"), pExportDirectory->AddressOfFunctions);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("AddressOfNameOrdinals: %X\r\n"), pExportDirectory->AddressOfNameOrdinals);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("AddressOfNames: %X\r\n"), pExportDirectory->AddressOfNames);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("Base: %X\r\n"), pExportDirectory->Base);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("Characteristics: %X\r\n"), pExportDirectory->Characteristics);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("MajorVersion: %X\r\n"), pExportDirectory->MajorVersion);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("MinorVersion: %X\r\n"), pExportDirectory->MinorVersion);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("Name: %X\r\n"), pExportDirectory->Name);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("NumberOfFunctions: %X\r\n"), pExportDirectory->NumberOfFunctions);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("NumberOfNames: %X\r\n"), pExportDirectory->NumberOfNames);
	AddText(hEdit, szBuffer);
	_stprintf(szBuffer, TEXT("TimeDateStamp: %X\r\n"), pExportDirectory->TimeDateStamp);
	AddText(hEdit, szBuffer);
	
	_stprintf(szBuffer, TEXT("\r\n----------------AddressOfFunctions----------------\r\n"));
	AddText(hEdit, szBuffer);
	
	PDWORD AddressOfFunctions = (PDWORD)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfFunctions));
	size_t i;
	for (i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{		
		_stprintf(szBuffer, TEXT("AddressOfFunctions[%d] = %X\r\n"), i, AddressOfFunctions[i]);
		AddText(hEdit, szBuffer);
	}
	
	_stprintf(szBuffer, TEXT("\r\n----------------AddressOfNames & AddressOfNameOridinals----------------\r\n"));
	AddText(hEdit, szBuffer);
	
	PDWORD AddressOfNames = (PDWORD)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNames));
	PWORD AddressOfNameOridinals = (PWORD)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals));
	
	for (i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		_stprintf(szBuffer, TEXT("AddressOfNames[%d] = %s, AddressOfOrdinals[%d] = %d\r\n"), \
			i, (LPCTSTR)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, AddressOfNames[i])), i, AddressOfNameOridinals[i]);
		AddText(hEdit, szBuffer);
	}	
}

// ��ӡ������IAT��
VOID PrintImportTable(HWND hEdit, LPCTSTR szFile)
{
	// ����PE�ļ�
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{		
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (pOptionHeader->DataDirectory[1].VirtualAddress == NULL)
	{
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));

	TCHAR szBuffer[0x200];
	
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// ��ӡģ����
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCTSTR)(RvaToFoa(pFileBuffer, pImportTable->Name) + (DWORD)pFileBuffer));
		AddText(hEdit, szBuffer);
		// ����INT��(import name table)
		_stprintf(szBuffer, TEXT("--------------INT RVA:%X--------------\r\n"), pImportTable->OriginalFirstThunk);
		AddText(hEdit, szBuffer);
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->OriginalFirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
			// ������λ��1����ô��ȥ���λ���ǵ������
			// ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{
				_stprintf(szBuffer, TEXT("����ŵ��� Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);				
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("�����ֵ��� Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);				
			}
			pThunkData++;
		}
		// ����IAT��(import address table)
		_stprintf(szBuffer, TEXT("--------------IAT RVA:%X--------------\r\n"), pImportTable->FirstThunk);
		AddText(hEdit, szBuffer);		
		pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->FirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
			// ������λ��1����ô��ȥ���λ���ǵ������
			// ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{				
				_stprintf(szBuffer, TEXT("����ŵ��� Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);	
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("�����ֵ��� Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		AddText(hEdit, "\r\n\r\n");
	}
}

// ��ӡ��Դ��
VOID PrintResourceTable(HWND hEdit, LPCTSTR szFile)
{
	//��Դ������
	LPCTSTR lpszResType[17] = { 
		TEXT("δ����"), 
		TEXT("���"), 
		TEXT("λͼ"), 
		TEXT("ͼ��"), 
		TEXT("�˵�"),
		TEXT("�Ի���"), 
		TEXT("�ַ���"),
		TEXT("����Ŀ¼"), 
		TEXT("����"),
		TEXT("���ټ�"), 
		TEXT("�Ǹ�ʽ����Դ"), 
		TEXT("��Ϣ�б�"), 
		TEXT("�����"),
		TEXT("δ����"), 
		TEXT("ͼ����"),
		TEXT("δ����"), 
		TEXT("�汾��Ϣ") 
	};
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	TCHAR szBuffer[0x200];
	if (pOptionHeader->DataDirectory[2].VirtualAddress == NULL)
	{
		return;
	}
	// �����һ���ָ��ͳ���
	PIMAGE_RESOURCE_DIRECTORY pResDir1 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[2].VirtualAddress));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir1 + \
		sizeof(IMAGE_RESOURCE_DIRECTORY));	
	int dwNumberOfResDirEntry1 = pResDir1->NumberOfNamedEntries + pResDir1->NumberOfIdEntries;
	_stprintf(szBuffer, TEXT("��Դ��������: %d\r\n"), dwNumberOfResDirEntry1);
	AddText(hEdit, szBuffer);
	//printf("��Դ��������: %d\n", dwNumberOfResDirEntry1);
	// ������һ�㣺����
	for (int i = 0; i < dwNumberOfResDirEntry1; i++)
	{
		// �����λ��1����31λ��ָ�룬ָ��һ��Unicode�ַ���
		if (pResDirEntry1[i].NameIsString == 1)
		{
			PIMAGE_RESOURCE_DIR_STRING_U uString = 
				(PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResDir1 + (pResDirEntry1[i].NameOffset & 0x7FFFFFFF));			
			WCHAR *pName = (WCHAR *)malloc(2 * (uString->Length + 1));
			memset(pName, 0, 2 * (uString->Length + 1));
			memcpy(pName, uString->NameString, 2 * uString->Length);			
			wsprintfW((LPWSTR)&szBuffer, L"ID:  - ��Դ����: \"%s\"\r\n", pName);
			AddTextW(hEdit, (LPCWSTR)&szBuffer);
			free(pName);			
		}
		// ������λ��0��������һ����ţ���Ԥ�����16����Դ֮һ
		else
		{
			if (pResDirEntry1[i].Id <= 16)
			{
				//printf("ID: %2d ��Դ����: %s\n", pResDirEntry1[i].Id, lpszResType[pResDirEntry1[i].Id]);
				_stprintf(szBuffer, TEXT("ID: %2d ��Դ����: %s\r\n"), pResDirEntry1[i].Id, lpszResType[pResDirEntry1[i].Id]);
				AddText(hEdit, szBuffer);
			}
			else
			{
				//printf("ID: %2d ��Դ����: δ����\n", pResDirEntry1[i].Id);
				_stprintf(szBuffer, TEXT("ID: %2d ��Դ����: δ����\r\n"), pResDirEntry1[i].Id);
				AddText(hEdit, szBuffer);
			}
		}
		// ����ڶ����ָ��ͳ���		
		PIMAGE_RESOURCE_DIRECTORY pResDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
			(pResDirEntry1[i].OffsetToData & 0x7FFFFFFF));
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir2 + \
			sizeof(IMAGE_RESOURCE_DIRECTORY));		
		int dwNumberOfResDirEntry1 = pResDir2->NumberOfNamedEntries + pResDir2->NumberOfIdEntries;
		// �����ڶ��㣺���		
		for (int j = 0; j < dwNumberOfResDirEntry1; j++)
		{
			if (pResDirEntry2[j].NameIsString == 1)
			{
				PIMAGE_RESOURCE_DIR_STRING_U uString = 
					(PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResDir1 + (pResDirEntry2[j].NameOffset & 0x7FFFFFFF));			
				WCHAR *pName = (WCHAR *)malloc(2 * (uString->Length + 1));
				memset(pName, 0, 2 * (uString->Length + 1));
				memcpy(pName, uString->NameString, 2 * uString->Length);				
				//wprintf(L"\tName: \"%s\"\n", pName);
				wsprintfW((LPWSTR)&szBuffer, L"\tName: \"%s\"\r\n", pName);
				AddTextW(hEdit, (LPCWSTR)&szBuffer);
				free(pName);
			}
			else
			{
				//printf("\tID: %d\n", pResDirEntry2[j].Id);
				_stprintf(szBuffer, TEXT("\tID: %d\r\n"), pResDirEntry2[j].Id);
				AddText(hEdit, szBuffer);
			}
			// ����������ָ��ͳ���		
			PIMAGE_RESOURCE_DIRECTORY pResDir3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
				(pResDirEntry2[j].OffsetToData & 0x7FFFFFFF));
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir3 + \
				sizeof(IMAGE_RESOURCE_DIRECTORY));		
			int dwNumberOfResDirEntry3 = pResDir3->NumberOfNamedEntries + pResDir3->NumberOfIdEntries;
			// ���������㣺����ҳ
			// ����������һ����Դ�Ĵ���ҳֻ����һ�֣������Ǿ��ԣ���˵�����ҲҪѭ������			
			//printf("\t\t%d\n", dwNumberOfResDirEntry3); // ���в���1��
			for (int k = 0; k < dwNumberOfResDirEntry3; k++)
			{
				if (pResDirEntry3[k].Name & 0x80000000)
				{
					_stprintf(szBuffer, TEXT("\t�Ǳ�׼����ҳ\r\n"));
					AddText(hEdit, szBuffer);
					//printf("\t�Ǳ�׼����ҳ\n");
				}
				else
				{
					//printf("\t����ҳ: %d\n", pResDirEntry3[k].Id & 0x7FFF);
					_stprintf(szBuffer, TEXT("\t����ҳ: %d\r\n"), pResDirEntry3[k].Id & 0x7FFF);
					AddText(hEdit, szBuffer);
				}
				// ��Դ�����ͨ������ṹ�����ҵ���Դ��RVA���Լ���С
				PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResDir1 + \
					pResDirEntry3[k].OffsetToData);
				_stprintf(szBuffer, TEXT("\tRVA: %X\tSIZE: %X\r\n"), pDataEntry->OffsetToData, pDataEntry->Size);
				AddText(hEdit, szBuffer);
				//printf("\tRVA: %x\tSIZE: %x\n", pDataEntry->OffsetToData, pDataEntry->Size);
			}
			//printf("\n");
			AddText(hEdit, TEXT("\r\n"));
		}
	}
}

// ��ӡ�ض�λ��
VOID PrintRelocationTable(HWND hEdit, LPCTSTR szFile)
{
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	//PIMAGE_SECTION_HEADER pSectionHeader = \
	//	(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (pOptionHeader->DataDirectory[5].VirtualAddress == NULL)
	{
		return;
	}
	PIMAGE_BASE_RELOCATION pBaseRelocation = \
		(PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[5].VirtualAddress));
	TCHAR szBuffer[0x200];
	
	while (pBaseRelocation->VirtualAddress || pBaseRelocation->SizeOfBlock)
	{
		AddText(hEdit, TEXT("-------------------------------------------------------------------\r\n"));
		_stprintf(szBuffer, TEXT("VirtualAddress = %08X\r\n"), pBaseRelocation->VirtualAddress);
		AddText(hEdit, szBuffer);
		_stprintf(szBuffer, TEXT("SizeOfBlock = %08X\r\n"), pBaseRelocation->SizeOfBlock);
		AddText(hEdit, szBuffer);		
		PWORD pwAddr = (PWORD)((DWORD)pBaseRelocation + 8);
		int n = (pBaseRelocation->SizeOfBlock - 8) / 2;		
		_stprintf(szBuffer, TEXT("Ҫ�޸ĵĵ�ַ���� = %d\r\n"), n);
		AddText(hEdit, szBuffer);
		for (int i = 0; i < n ; i++)
		{
			WORD wProp = (0xF000 & pwAddr[i]) >> 12;
			WORD wAddr = 0x0FFF & pwAddr[i];
			_stprintf(szBuffer, TEXT("[%d]��RVA = %08X\t���� = %d\r\n"), i+1, pBaseRelocation->VirtualAddress + wAddr, wProp);
			AddText(hEdit, szBuffer);			
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		AddText(hEdit, TEXT("\r\n"));
	}	
}

// ��ӡ�󶨵����
VOID PrintBoundImportTable(HWND hEdit, LPCTSTR szFile)
{
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (pOptionHeader->DataDirectory[1].VirtualAddress == NULL)
	{
		return;
	}
	// �жϷ�ʽһ
	/*if (NULL == pOptionHeader->DataDirectory[11].VirtualAddress)
	{
		printf("�ó���󶨵����Ϊ��\n");
		return;
	}*/
	// �жϷ�ʽ��	
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));
	if (pImportTable->TimeDateStamp == 0)
	{
		//printf("�ó���û�а󶨵���\n");
		return;
	}
	TCHAR szBuffer[0x200];
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[11].VirtualAddress));
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirstBoundImportTable = pBoundImportTable;	
	
	while (pBoundImportTable->TimeDateStamp || pBoundImportTable->OffsetModuleName || pBoundImportTable->NumberOfModuleForwarderRefs)
	{
		// ��ӡʱ�����ģ����������ģ������
		AddText(hEdit, TEXT("-------------------------------------------------------------------\r\n"));
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCSTR)((DWORD)pFirstBoundImportTable + pBoundImportTable->OffsetModuleName));
		AddText(hEdit, szBuffer);
		_stprintf(szBuffer, TEXT("TimeDateStamp:%x\r\n"), pBoundImportTable->TimeDateStamp);
		AddText(hEdit, szBuffer);
		_stprintf(szBuffer, TEXT("NumberOfModuleForwarderRefs:%d\r\n"), pBoundImportTable->NumberOfModuleForwarderRefs);
		AddText(hEdit, szBuffer);		
		// ��������ģ��
		PIMAGE_BOUND_FORWARDER_REF pBFR = (PIMAGE_BOUND_FORWARDER_REF)((DWORD)pBoundImportTable + \
			sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
		for (size_t i = 0; i < pBoundImportTable->NumberOfModuleForwarderRefs; i++)
		{
			_stprintf(szBuffer, TEXT("\t%s\r\n"), (LPCSTR)((DWORD)pFirstBoundImportTable + pBFR[i].OffsetModuleName));
			AddText(hEdit, szBuffer);
			_stprintf(szBuffer, TEXT("\tTimeDateStamp: %X\r\n"), pBFR[i].TimeDateStamp);
			AddText(hEdit, szBuffer);
		}
		pBoundImportTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pBoundImportTable + \
			sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + \
			pBoundImportTable->NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF));
	}

}

// ��ӡIAT��
VOID PrintIATTable(HWND hEdit, LPCTSTR szFile)
{
	// ����PE�ļ�
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{		
		return;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (pOptionHeader->DataDirectory[1].VirtualAddress == NULL)
	{
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));
	
	TCHAR szBuffer[0x200];
	
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// ��ӡģ����
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCTSTR)(RvaToFoa(pFileBuffer, pImportTable->Name) + (DWORD)pFileBuffer));
		AddText(hEdit, szBuffer);		
		// ����IAT��(import address table)
		_stprintf(szBuffer, TEXT("--------------IAT RVA:%X--------------\r\n"), pImportTable->FirstThunk);
		AddText(hEdit, szBuffer);		
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->FirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
			// ������λ��1����ô��ȥ���λ���ǵ������
			// ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{				
				_stprintf(szBuffer, TEXT("����ŵ��� Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);	
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("�����ֵ��� Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		AddText(hEdit, "\r\n\r\n");
	}
}