#include "stdafx.h"
#include "PE.h"

// 验证是否PE文件
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
		printf("不是有效的MZ标志\n");
		return FALSE;
	}
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标记\n");
		return FALSE;
	}
	
	return TRUE;
}

// RVA 转 FOA
DWORD RvaToFoa(LPVOID pFileBuffer, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	// RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的
	if (dwRva < pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}
	
	// 遍历节表，确定偏移属于哪一个节	
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && \
			dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
		{
			int offset = dwRva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}
	printf("找不到RVA %x 对应的 FOA，转换失败\n", dwRva);
	return 0;
}

// 读取PE文件到内存中，返回读取的字节数；读取失败返回0
DWORD ReadPEFile(LPCTSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = _tfopen(lpszFile, TEXT("rb"));
	if (pFile == NULL) 
	{
		printf("打开文件失败\n");
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

// 根据文件名，解析PE文件，将信息显示到 PEInfoDialog
BOOL PrintPEInfo(HWND hDlg, LPCTSTR szFile)
{
	// 解析PE文件
	LPVOID pFileBuffer = NULL;
	DWORD dwFileSize = ReadPEFile(szFile, &pFileBuffer);
	if (dwFileSize == 0 || pFileBuffer == NULL)
	{
		MessageBox(hDlg, TEXT("文件不存在"), TEXT("Error"), MB_OK);
		return FALSE;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);	

	// 获取文本框句柄
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

	// 定义字符缓冲区
	const int cbBuffer = 0x100;
	TCHAR szBuffer[cbBuffer];

	// 输出
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

// 根据文件名，解析PE文件，将节表信息显示到 PESectionDialog
BOOL PrintSectionInfo(HWND hDlg, LPCTSTR szFile)
{
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTIONS);
	TCHAR szBuffer[0x200];
	LV_ITEM vItem;
	memset(&vItem, 0, sizeof(LV_ITEM));
	vItem.mask = LVIF_TEXT;
	
	// 解析PE文件
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

	// 遍历节表
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		// 节名称
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		memcpy(szBuffer, pSectionHeader[i].Name, 8);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 0; // 列
		ListView_InsertItem(hListSection, &vItem);
		// 内存偏移
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].VirtualAddress);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 1; // 列
		ListView_SetItem(hListSection, &vItem);
		// 内存大小
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].Misc.VirtualSize);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 2; // 列
		ListView_SetItem(hListSection, &vItem);
		// 文件偏移
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].PointerToRawData);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 3; // 列
		ListView_SetItem(hListSection, &vItem);
		// 文件大小
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].SizeOfRawData);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 4; // 列
		ListView_SetItem(hListSection, &vItem);
		// 属性
		memset(szBuffer, 0, 0x200 * sizeof(TCHAR));
		_stprintf(szBuffer, TEXT("%X"), pSectionHeader[i].Characteristics);
		vItem.pszText = szBuffer;
		vItem.iItem = i;	// 行
		vItem.iSubItem = 5; // 列
		ListView_SetItem(hListSection, &vItem);
	}	
	return TRUE;
}

// 打印目录项信息到目录项对话框
BOOL PrintDirInfo(HWND hDlg, LPCTSTR szFile)
{
	// 初始化文本框句柄
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

	// 打印数据目录
	TCHAR szBuffer[0x200];
	LPVOID pFileBuffer = NULL;
	if (ReadPEFile(szFile, &pFileBuffer) == 0)
	{
		MessageBox(hDlg, TEXT("文件不存在"), TEXT("Error"), MB_OK);
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

// 打印导出表
VOID PrintExportTable(HWND hEdit, LPCTSTR szFile)
{
	// 解析PE文件
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
	// 打印
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

// 打印导入表和IAT表
VOID PrintImportTable(HWND hEdit, LPCTSTR szFile)
{
	// 解析PE文件
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
		// 打印模块名
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCTSTR)(RvaToFoa(pFileBuffer, pImportTable->Name) + (DWORD)pFileBuffer));
		AddText(hEdit, szBuffer);
		// 遍历INT表(import name table)
		_stprintf(szBuffer, TEXT("--------------INT RVA:%X--------------\r\n"), pImportTable->OriginalFirstThunk);
		AddText(hEdit, szBuffer);
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->OriginalFirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 是一个4字节数据
			// 如果最高位是1，那么除去最高位就是导出序号
			// 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{
				_stprintf(szBuffer, TEXT("按序号导入 Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);				
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("按名字导入 Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);				
			}
			pThunkData++;
		}
		// 遍历IAT表(import address table)
		_stprintf(szBuffer, TEXT("--------------IAT RVA:%X--------------\r\n"), pImportTable->FirstThunk);
		AddText(hEdit, szBuffer);		
		pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->FirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 是一个4字节数据
			// 如果最高位是1，那么除去最高位就是导出序号
			// 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{				
				_stprintf(szBuffer, TEXT("按序号导入 Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);	
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("按名字导入 Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		AddText(hEdit, "\r\n\r\n");
	}
}

// 打印资源表
VOID PrintResourceTable(HWND hEdit, LPCTSTR szFile)
{
	//资源的类型
	LPCTSTR lpszResType[17] = { 
		TEXT("未定义"), 
		TEXT("光标"), 
		TEXT("位图"), 
		TEXT("图标"), 
		TEXT("菜单"),
		TEXT("对话框"), 
		TEXT("字符串"),
		TEXT("字体目录"), 
		TEXT("字体"),
		TEXT("加速键"), 
		TEXT("非格式化资源"), 
		TEXT("消息列表"), 
		TEXT("光标组"),
		TEXT("未定义"), 
		TEXT("图标组"),
		TEXT("未定义"), 
		TEXT("版本信息") 
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
	// 定义第一层的指针和长度
	PIMAGE_RESOURCE_DIRECTORY pResDir1 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[2].VirtualAddress));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir1 + \
		sizeof(IMAGE_RESOURCE_DIRECTORY));	
	int dwNumberOfResDirEntry1 = pResDir1->NumberOfNamedEntries + pResDir1->NumberOfIdEntries;
	_stprintf(szBuffer, TEXT("资源类型数量: %d\r\n"), dwNumberOfResDirEntry1);
	AddText(hEdit, szBuffer);
	//printf("资源类型数量: %d\n", dwNumberOfResDirEntry1);
	// 遍历第一层：类型
	for (int i = 0; i < dwNumberOfResDirEntry1; i++)
	{
		// 如果高位是1，低31位是指针，指向一个Unicode字符串
		if (pResDirEntry1[i].NameIsString == 1)
		{
			PIMAGE_RESOURCE_DIR_STRING_U uString = 
				(PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResDir1 + (pResDirEntry1[i].NameOffset & 0x7FFFFFFF));			
			WCHAR *pName = (WCHAR *)malloc(2 * (uString->Length + 1));
			memset(pName, 0, 2 * (uString->Length + 1));
			memcpy(pName, uString->NameString, 2 * uString->Length);			
			wsprintfW((LPWSTR)&szBuffer, L"ID:  - 资源类型: \"%s\"\r\n", pName);
			AddTextW(hEdit, (LPCWSTR)&szBuffer);
			free(pName);			
		}
		// 如果最高位是0，则这是一个序号，是预定义的16种资源之一
		else
		{
			if (pResDirEntry1[i].Id <= 16)
			{
				//printf("ID: %2d 资源类型: %s\n", pResDirEntry1[i].Id, lpszResType[pResDirEntry1[i].Id]);
				_stprintf(szBuffer, TEXT("ID: %2d 资源类型: %s\r\n"), pResDirEntry1[i].Id, lpszResType[pResDirEntry1[i].Id]);
				AddText(hEdit, szBuffer);
			}
			else
			{
				//printf("ID: %2d 资源类型: 未定义\n", pResDirEntry1[i].Id);
				_stprintf(szBuffer, TEXT("ID: %2d 资源类型: 未定义\r\n"), pResDirEntry1[i].Id);
				AddText(hEdit, szBuffer);
			}
		}
		// 定义第二层的指针和长度		
		PIMAGE_RESOURCE_DIRECTORY pResDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
			(pResDirEntry1[i].OffsetToData & 0x7FFFFFFF));
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir2 + \
			sizeof(IMAGE_RESOURCE_DIRECTORY));		
		int dwNumberOfResDirEntry1 = pResDir2->NumberOfNamedEntries + pResDir2->NumberOfIdEntries;
		// 遍历第二层：编号		
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
			// 定义第三层的指针和长度		
			PIMAGE_RESOURCE_DIRECTORY pResDir3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
				(pResDirEntry2[j].OffsetToData & 0x7FFFFFFF));
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir3 + \
				sizeof(IMAGE_RESOURCE_DIRECTORY));		
			int dwNumberOfResDirEntry3 = pResDir3->NumberOfNamedEntries + pResDir3->NumberOfIdEntries;
			// 遍历第三层：代码页
			// 大多数情况下一个资源的代码页只定义一种，但不是绝对，因此第三层也要循环遍历			
			//printf("\t\t%d\n", dwNumberOfResDirEntry3); // 真有不是1的
			for (int k = 0; k < dwNumberOfResDirEntry3; k++)
			{
				if (pResDirEntry3[k].Name & 0x80000000)
				{
					_stprintf(szBuffer, TEXT("\t非标准代码页\r\n"));
					AddText(hEdit, szBuffer);
					//printf("\t非标准代码页\n");
				}
				else
				{
					//printf("\t代码页: %d\n", pResDirEntry3[k].Id & 0x7FFF);
					_stprintf(szBuffer, TEXT("\t代码页: %d\r\n"), pResDirEntry3[k].Id & 0x7FFF);
					AddText(hEdit, szBuffer);
				}
				// 资源数据项，通过这个结构可以找到资源的RVA，以及大小
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

// 打印重定位表
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
		_stprintf(szBuffer, TEXT("要修改的地址个数 = %d\r\n"), n);
		AddText(hEdit, szBuffer);
		for (int i = 0; i < n ; i++)
		{
			WORD wProp = (0xF000 & pwAddr[i]) >> 12;
			WORD wAddr = 0x0FFF & pwAddr[i];
			_stprintf(szBuffer, TEXT("[%d]：RVA = %08X\t属性 = %d\r\n"), i+1, pBaseRelocation->VirtualAddress + wAddr, wProp);
			AddText(hEdit, szBuffer);			
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		AddText(hEdit, TEXT("\r\n"));
	}	
}

// 打印绑定导入表
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
	// 判断方式一
	/*if (NULL == pOptionHeader->DataDirectory[11].VirtualAddress)
	{
		printf("该程序绑定导入表为空\n");
		return;
	}*/
	// 判断方式二	
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));
	if (pImportTable->TimeDateStamp == 0)
	{
		//printf("该程序没有绑定导入\n");
		return;
	}
	TCHAR szBuffer[0x200];
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[11].VirtualAddress));
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirstBoundImportTable = pBoundImportTable;	
	
	while (pBoundImportTable->TimeDateStamp || pBoundImportTable->OffsetModuleName || pBoundImportTable->NumberOfModuleForwarderRefs)
	{
		// 打印时间戳、模块名、依赖模块数量
		AddText(hEdit, TEXT("-------------------------------------------------------------------\r\n"));
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCSTR)((DWORD)pFirstBoundImportTable + pBoundImportTable->OffsetModuleName));
		AddText(hEdit, szBuffer);
		_stprintf(szBuffer, TEXT("TimeDateStamp:%x\r\n"), pBoundImportTable->TimeDateStamp);
		AddText(hEdit, szBuffer);
		_stprintf(szBuffer, TEXT("NumberOfModuleForwarderRefs:%d\r\n"), pBoundImportTable->NumberOfModuleForwarderRefs);
		AddText(hEdit, szBuffer);		
		// 遍历依赖模块
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

// 打印IAT表
VOID PrintIATTable(HWND hEdit, LPCTSTR szFile)
{
	// 解析PE文件
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
		// 打印模块名
		_stprintf(szBuffer, TEXT("%s\r\n"), (LPCTSTR)(RvaToFoa(pFileBuffer, pImportTable->Name) + (DWORD)pFileBuffer));
		AddText(hEdit, szBuffer);		
		// 遍历IAT表(import address table)
		_stprintf(szBuffer, TEXT("--------------IAT RVA:%X--------------\r\n"), pImportTable->FirstThunk);
		AddText(hEdit, szBuffer);		
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pFileBuffer + \
			RvaToFoa(pFileBuffer, pImportTable->FirstThunk));
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 是一个4字节数据
			// 如果最高位是1，那么除去最高位就是导出序号
			// 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{				
				_stprintf(szBuffer, TEXT("按序号导入 Ordinal:%04X\r\n"), (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				AddText(hEdit, szBuffer);	
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pFileBuffer, *((PDWORD)pThunkData)) + \
					(DWORD)pFileBuffer);
				_stprintf(szBuffer, TEXT("按名字导入 Hint:%04X Name:%s\r\n"), pIBN->Hint, pIBN->Name);
				AddText(hEdit, szBuffer);
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		AddText(hEdit, "\r\n\r\n");
	}
}