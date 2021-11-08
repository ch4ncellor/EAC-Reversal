char __fastcall EAC::HWID::GetMACAddress(__int64 a1, void *a2)
{
  char v2; // bl
  int v4; // [rsp+20h] [rbp-28h] BYREF
  void *v5; // [rsp+28h] [rbp-20h]
  char v6; // [rsp+30h] [rbp-18h]

  v2 = 0;
  v4 = a1;
  v5 = a2;
  v6 = 0;
  if ( !a2 || a1 != 6 )
    return 0;
  if ( EAC::HWID::GetFirstNetworkDeviceMacAddress(a1, a2, &v4) )
  {
    if ( v6 )
      v2 = 1;
  }
  return v2;
}

char __fastcall EAC::HWID::GetFirstNetworkDeviceMacAddress(__int64 a1, void *a2, __int64 a3)
{
  __int64 v4; // r14
  char v5; // si
  int (__fastcall *v6)(void *, _QWORD, __int64, PVOID *); // rax
  __int64 v7; // r8
  char *v8; // rcx
  char *v9; // rbx
  __int64 v10; // r8
  unsigned __int32 v11; // edx
  unsigned __int64 v12; // rdi
  __int64 v13; // r8
  __int64 v14; // r9
  __int64 v15; // rax
  __int64 i; // r14
  char *v17; // rbx
  __int64 v18; // r8
  unsigned int v19; // edx
  unsigned __int64 v20; // rdi
  __int64 v21; // r8
  __int64 v22; // r9
  __int64 v23; // rax
  __int64 v24; // rdi
  char *v25; // rdx
  __int64 v26; // r9
  char v27; // al
  __int64 v28; // rdx
  int v30[4]; // [rsp+20h] [rbp-50h]
  int v31[4]; // [rsp+30h] [rbp-40h]
  char v32[16]; // [rsp+40h] [rbp-30h] BYREF
  __int128 v33; // [rsp+50h] [rbp-20h] BYREF
  __int128 v34; // [rsp+60h] [rbp-10h] BYREF
  PVOID P; // [rsp+B8h] [rbp+48h] BYREF
  __int128 *v36; // [rsp+C8h] [rbp+58h]

  P = a2;
  v4 = 0i64;
  v5 = 1;
  if ( KeGetCurrentIrql() )
    return 0;
  v6 = EAC::Memory::ResolveImportWrapper(*IoGetDeviceInterfaces, IoGetDeviceInterfaces, 0i64);
  if ( !v6 || v6(&unk_14006E450, 0i64, v7, &P) < 0 )
    return 0;
  v8 = P;
  do
  {
    v9 = &v8[2 * v4];
    if ( !*v9 )
      break;
    v10 = -1i64;
    do
      ++v10;
    while ( *&v9[2 * v10] );
    v30[0] = -1172472817;
    v30[1] = -1869928664;
    v33 = 0i64;
    v30[2] = 2023745324;
    v11 = 861309531;
    v30[3] = 858689899;
    v12 = 0i64;
    v36 = &v33;
    do
    {
      v11 = _byteswap_ulong(((v11 ^ (v11 >> 7)) << 9) ^ v11 ^ (v11 >> 7) ^ ((((v11 ^ (v11 >> 7)) << 9) ^ v11 ^ (v11 >> 7)) >> 13));
      *(v36 + v12 * 4) = v30[v12] ^ v11;
      ++v12;
    }
    while ( v12 < 4 );
    v13 = sub_140007C9C(v9, &v33);
    memset(&v33, 0, sizeof(v33));
    if ( v13 == v9 )
    {
      EAC::Memory::InitializeUnicodeStringWithCString(v32, v9);
      v5 = EAC::HWID::GetMacAddressSecondary(0i64, v32, a3, v14);
    }
    v8 = P;
    v15 = -1i64;
    do
      ++v15;
    while ( *(P + v4 + v15) );
    v4 += v15 + 1;
  }
  while ( v5 );
  for ( i = 0i64; v5; i += v23 + 1 )
  {
    v17 = &v8[2 * i];
    if ( !*v17 )
      break;
    v18 = -1i64;
    do
      ++v18;
    while ( *&v17[2 * v18] );
    v31[0] = -893088486;
    v31[1] = 781382351;
    v34 = 0i64;
    v31[2] = 489497106;
    v19 = 1526199263;
    v31[3] = 1870561;
    v20 = 0i64;
    v36 = &v34;
    do
    {
      v19 = ~(((v19 ^ (v19 << 13)) >> 17) ^ v19 ^ (v19 << 13) ^ (32 * (((v19 ^ (v19 << 13)) >> 17) ^ v19 ^ (v19 << 13))));
      *(v36 + v20 * 4) = v31[v20] ^ v19;
      ++v20;
    }
    while ( v20 < 4 );
    v21 = sub_140007C9C(v17, &v34);
    memset(&v34, 0, sizeof(v34));
    if ( v21 == v17 )
    {
      EAC::Memory::InitializeUnicodeStringWithCString(v32, v17);
      v5 = EAC::HWID::GetMacAddressSecondary(1i64, v32, a3, v22);
    }
    v8 = P;
    v23 = -1i64;
    do
      ++v23;
    while ( *(P + i + v23) );
  }
  v24 = 0i64;
  if ( v5 )
  {
    do
    {
      v25 = &v8[2 * v24];
      if ( !*v25 )
        break;
      EAC::Memory::InitializeUnicodeStringWithCString(v32, v25);
      v27 = EAC::HWID::GetMacAddressSecondary(2i64, v32, a3, v26);
      v8 = P;
      v28 = -1i64;
      do
        ++v28;
      while ( *(P + v24 + v28) );
      v24 += v28 + 1;
    }
    while ( v27 );
  }
  ExFreePoolWithTag(v8, 0);
  return 1;
}

char __fastcall EAC::HWID::CollectProcessorFeatures(__int64 a1)
{
  unsigned int v2; // ebx
  __int128 *v4; // r8
  __int16 *v5; // rdx
  __int64 v6; // rax
  wchar_t *v7; // rcx
  __int128 v8; // [rsp+20h] [rbp-A8h] BYREF
  int v9; // [rsp+30h] [rbp-98h]
  __m128 v10[8]; // [rsp+40h] [rbp-88h] BYREF

  v9 = 0;
  v8 = 0i64;
  EAC::Memory::memset(v10, 0, 0x80ui64);
  v2 = 0;
  if ( !a1 )
    return 0;
  EAC::HWID::HashVar(0xFFFFF78000000274ui64, 0x40u, &v8);// ProcessorFeatures
  v4 = &v8;
  v5 = &v10[0].m128_i16[1];
  do
  {
    v6 = *v4;
    ++v2;
    v4 = (v4 + 1);
    v7 = off_1400534C0[v6];
    *(v5 - 1) = *v7;
    *v5 = v7[1];
    v5 += 2;
  }
  while ( v2 < 0x14 );
  return CreateUnicodeStringFromPWSTR(a1, v10);
}

char __fastcall EAC::HWID::HashFileInfromation(__int64 CurrentProcess, struct_pHWIDStruct *pHWIDStruct)
{
  __int64 bGetFileOnDisk; // rcx
  struct_pScanned_1 *pScanned; // rax
  struct_pScanned_1 *_pScanned; // rdi
  char v8[56]; // [rsp+20h] [rbp-38h] BYREF

  // Not sure if this is even a HWID related function.. It's probably them just sending process info to their servers.
  if ( !CurrentProcess || !pHWIDStruct || !EAC::Imports::PsGetProcessExitProcessCalled(CurrentProcess) )
    return 0;
  memset(pHWIDStruct, 0, 0x338ui64);
  if ( EAC::Callbacks::KeStackAttachProcess(CurrentProcess, v8) )
  {
    LOBYTE(bGetFileOnDisk) = 1;
    pScanned = EAC::Calbacks::ScanProcess(bGetFileOnDisk);
    _pScanned = pScanned;
    if ( pScanned )
    {
      pHWIDStruct->byte100 = *(pScanned->pInfoStruct + 30i64);
      EAC::Memory::CopyUnicodeStringToAnsiBuffer(pHWIDStruct, 256i64, &pScanned->unsigned___int1618);
      pHWIDStruct->dword104 = *(_pScanned->pInfoStruct + 0x250i64);
      pHWIDStruct->dword10C = *(_pScanned->pInfoStruct + 0x240i64);
      pHWIDStruct->dword108 = *(_pScanned->pInfoStruct + 0x234i64);
      pHWIDStruct->dword130 = *(_pScanned->pInfoStruct + 0x24Ci64);
      pHWIDStruct->dword134 = *(_pScanned->pInfoStruct + 0x248i64);
      EAC::Memory::CopyRawDataFromDebugDirectory(*(_pScanned->pInfoStruct + 14i64), &pHWIDStruct[1], 256);
      pHWIDStruct->nMicrosoftFileHash = EAC::HWID::HashMicrosoftFilesWrapper(*(_pScanned->pInfoStruct + 0xEi64));
      pHWIDStruct->qword120 = EAC::HWID::HashMoreFileShitNotSureWhatWrapper(*(_pScanned->pInfoStruct + 0xEi64));
      pHWIDStruct->qword128 = EAC::HWID::HashDosHeadersWrapper(*(_pScanned->pInfoStruct + 0xEi64));
      EAC::Memory::FreePoolAndUnicodeString(_pScanned);
    }
    EAC::Callbacks::KeUnstackDetachProcess(CurrentProcess, v8);
  }
  return 1;
}

char __fastcall EAC::HWID::SetNTOSKRNLOptionalHeaderHash(unsigned __int64 pCurrentFileBeingReadInMemory, unsigned int a2, _OWORD *pOutput)
{
  char bGrabbedHWID; // di
  __int64 v6; // rsi
  _IMAGE_NT_HEADERS64 *v7; // rax
  IMAGE_DATA_DIRECTORY *v8; // r8
  unsigned __int64 v9; // rax
  __int64 v10; // rdx
  unsigned __int64 v11; // rsi
  unsigned __int64 v12; // rcx
  unsigned int v13; // er14
  _IMAGE_NT_HEADERS64 *v14; // rdx
  char *v15; // rax
  unsigned int v16; // ecx
  __int64 v17; // rbx

  bGrabbedHWID = 0;
  if ( pOutput )
  {
    if ( pCurrentFileBeingReadInMemory )
    {
      v6 = a2;
      v7 = EAC::Memory::GetImageBase(pCurrentFileBeingReadInMemory, a2);
      if ( v7 )
      {
        v8 = &v7->OptionalHeader.DataDirectory[4];
        if ( v7->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
          v8 = &v7->OptionalHeader.DataDirectory[6];
        if ( v8->VirtualAddress )
        {
          if ( v8->Size )
          {
            v9 = sub_14004EC8C(v8->VirtualAddress, v7, pCurrentFileBeingReadInMemory);
            if ( v9 >= pCurrentFileBeingReadInMemory && v9 + 28 > v9 )
            {
              v11 = pCurrentFileBeingReadInMemory + v6;
              if ( v9 + 28 <= v11 )
              {
                v12 = *(v9 + 20);
                if ( v12 )
                {
                  v13 = *(v9 + 16);
                  if ( v13 )
                  {
                    if ( *(v9 + 12) == 2 )
                    {
                      v14 = sub_14004EC8C(v12, v10, pCurrentFileBeingReadInMemory);
                      if ( v14 >= pCurrentFileBeingReadInMemory )
                      {
                        v15 = v14 + v13;
                        if ( v15 > v14 && v15 <= v11 && v14->Signature == 'SDSR' )
                        {
                          v16 = 255;
                          if ( v13 - 25 < 0xFF )
                            v16 = v13 - 25;
                          v17 = v16;
                          EAC::Memory::memmove(pOutput, &v14->OptionalHeader, v16);
                          *(pOutput + v17) = 0;
                          bGrabbedHWID = 1;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return bGrabbedHWID;
}

unsigned __int64 __fastcall EAC::HWID::HashMicrosoftFiles(unsigned __int64 a1, unsigned int CONSTANT_4096)
{
  __m128 *v4; // rsi
  _IMAGE_NT_HEADERS64 *pOptionalHeaders; // rcx
  __int64 nSizeOfCode; // rbx
  _IMAGE_NT_HEADERS64 *v7; // rdx
  ULONG *nNumberOfSymbols; // rcx
  __int128 pHashed; // [rsp+28h] [rbp-E0h] BYREF
  unsigned int nLiterallyZero; // [rsp+38h] [rbp-D0h]
  __m128 pOriginalStruct_MaybeIdk[32]; // [rsp+48h] [rbp-C0h] BYREF

  EAC::Memory::memset(pOriginalStruct_MaybeIdk, 0, 0x200ui64);
  v4 = pOriginalStruct_MaybeIdk;
  nLiterallyZero = 0;
  pHashed = 0i64;
  if ( a1 )
  {
    if ( CONSTANT_4096 >= 512 )
    {
      pOptionalHeaders = EAC::Memory::GetImageBase(a1, CONSTANT_4096);
      if ( pOptionalHeaders )
      {
        while ( pOptionalHeaders > a1 )
        {
          pOptionalHeaders = (pOptionalHeaders - 4);
          if ( pOptionalHeaders->Signature == 'hciR' )// (END MARKER)
          {
            if ( pOptionalHeaders > a1 )
            {
              nSizeOfCode = *&pOptionalHeaders->FileHeader.Machine;
              v7 = pOptionalHeaders;
              while ( pOptionalHeaders > a1 )
              {
                pOptionalHeaders = (pOptionalHeaders - 4);
                if ( (pOptionalHeaders->Signature ^ nSizeOfCode) == 'SnaD' )// (START MARKER)
                {
                  if ( pOptionalHeaders <= a1 )
                    return 0i64;
                  if ( *&pOptionalHeaders->FileHeader.Machine != nSizeOfCode )
                    return 0i64;
                  if ( pOptionalHeaders->FileHeader.TimeDateStamp != nSizeOfCode )
                    return 0i64;
                  if ( pOptionalHeaders->FileHeader.PointerToSymbolTable != nSizeOfCode )
                    return 0i64;
                  nNumberOfSymbols = &pOptionalHeaders->FileHeader.NumberOfSymbols;
                  if ( (((v7 - nNumberOfSymbols) >> 2) - 2) > 126 )
                    return 0i64;
                  while ( nNumberOfSymbols < v7 )
                  {
                    v4->m128_i32[0] = *nNumberOfSymbols ^ nSizeOfCode;
                    v4 = (v4 + 4);
                    ++nNumberOfSymbols;
                  }
                  EAC::HWID::HashVar(pOriginalStruct_MaybeIdk, v4 - pOriginalStruct_MaybeIdk, &pHashed);
                  return nLiterallyZero ^ DWORD2(pHashed) ^ pHashed | ((nSizeOfCode ^ HIDWORD(pHashed) ^ DWORD1(pHashed)) << 32);
                }
              }
            }
            return 0i64;
          }
        }
      }
    }
  }
  return 0i64;
}

unsigned __int64 __fastcall EAC::HWID::HashDosHeaders(__int64 a1, unsigned int CONSTANT_4096)
{
  _IMAGE_NT_HEADERS64 *pNtHeaders; // rax
  __int64 ntype; // rcx
  __int128 v5; // [rsp+20h] [rbp-28h] BYREF
  unsigned int v6; // [rsp+30h] [rbp-18h]

  v6 = 0;
  v5 = 0i64;
  if ( !a1 )
    return 0i64;
  if ( CONSTANT_4096 < 512 )
    return 0i64;
  pNtHeaders = EAC::Memory::GetImageBase(a1, CONSTANT_4096);
  if ( !pNtHeaders )
    return 0i64;
  ntype = 120i64;
  if ( pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
    ntype = 136i64;
  EAC::HWID::HashVar(pNtHeaders + ntype, 0x80u, &v5);
  return ((HIDWORD(v5) ^ DWORD1(v5)) << 32) | v6 ^ DWORD2(v5) ^ v5;
}

char __fastcall EAC::HWID::HashNTOSKRNLInformation(__int64 pInputStruct, struct_a2 *pOutputStruct)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v2 = 0i64;
  P = 0i64;
  FileLength = 0;
  bHasPassedAlotOfChecksWtf = 0;
  UNICODESTR = 0i64;
  if ( !pOutputStruct || !pInputStruct || !*(pInputStruct + 8) || !*pInputStruct || !*(pInputStruct + 2) )
    return 0;
  memset(pOutputStruct, 0, 0x338ui64);
  EAC::Memory::CopyUnicodeStringToAnsiBuffer(pOutputStruct, 256i64, pInputStruct);
  if ( EAC::Memory::CopyOverUnicodeString(v5, &UNICODESTR) )// \SystemRoot\system32\ntoskrnl.exe
  {
    if ( EAC::Memory::ForceReadFile(&UNICODESTR, &P, &FileLength) )// calls ZwReadFile and sets parameters with info
    {
      Size = FileLength;
      pCurrentFileBeingReadInMemory = P;
      v41 = FileLength;
      if ( P && FileLength )
      {
        bHasCompletedScan = 0;
        v9 = P + FileLength;
        P = v9;
        if ( FileLength )                       // all this block of code does is set bHasPassedAlotOfChecksWtf after checking if file is valid enough
        {
          v10 = 0i64;
          pNTHeaders_1 = EAC::Memory::GetImageBase(pCurrentFileBeingReadInMemory, FileLength);
          if ( pNTHeaders_1 )
          {
            v12 = 152i64;
            if ( pNTHeaders_1->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
              v12 = 168i64;
            pDOSHeaders_1 = (pNTHeaders_1 + v12);
            if ( pDOSHeaders_1 )
            {
              if ( pDOSHeaders_1 >= pCurrentFileBeingReadInMemory
                && pDOSHeaders_1 + 2 > pDOSHeaders_1
                && pDOSHeaders_1 + 2 <= v9 )
              {
                v14 = pDOSHeaders_1[1];
                if ( v14 )
                {
                  e_magic = *pDOSHeaders_1;
                  if ( *pDOSHeaders_1 )
                  {
                    for ( i = 0; i < v14; i += *&nCurrentSectionSignatureMaybe->e_magic )
                    {
                      nCurrentSectionSignatureMaybe = (pCurrentFileBeingReadInMemory + e_magic + i);
                      if ( nCurrentSectionSignatureMaybe < pCurrentFileBeingReadInMemory
                        || &nCurrentSectionSignatureMaybe->e_maxalloc <= nCurrentSectionSignatureMaybe
                        || &nCurrentSectionSignatureMaybe->e_maxalloc > P
                        || !*&nCurrentSectionSignatureMaybe->e_magic )
                      {
                        break;
                      }
                      if ( nCurrentSectionSignatureMaybe->e_crlc == 2 )
                      {
                        v10 = pCurrentFileBeingReadInMemory + e_magic + i;
                        bHasCompletedScan = 1;
                        break;
                      }
                    }
                    if ( bHasCompletedScan )
                    {
                      v18 = *v10;
                      v19 = (v10 + 8);
                      v20 = v18 - 8;
                      if ( v19 >= pCurrentFileBeingReadInMemory )
                      {
                        v21 = &v19[v20];
                        if ( v21 > v19 && v21 <= &v41[pCurrentFileBeingReadInMemory] )
                        {
                          v22 = EAC::Memory::ExAllocatePoolWithRandomTag2(72i64);
                          v2 = v22;
                          if ( v22 )
                          {
                            v44 = 0i64;
                            v41 = v19;
                            LODWORD(P) = v20;
                            memset(v22, 0, 0x48ui64);
                            v42 = 0i64;
                            v43 = 0i64;
                            if ( v19
                              && v20
                              && (memset(v22, 0, 0x48ui64), sub_140049E28(1, &v41, &P, &v42))
                              && v42 == 16
                              && sub_140049E28(1, &v41, &P, &v42)
                              && v42 == 6
                              && v43 == 9
                              && **(&v42 + 1) == 0x7010DF78648862Ai64
                              && *(*(&v42 + 1) + 8i64) == 2
                              && sub_140049E28(1, &v41, &P, &v42)
                              && !v42
                              && sub_140049E28(1, &v41, &P, &v42)
                              && v42 == 16
                              && v43
                              && sub_140035494(*(&v42 + 1), v43, v2) )
                            {
                              bHasPassedAlotOfChecksWtf = 1;
                            }
                            else
                            {
                              EAC::Memory::ExFreePool(v2);
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          Size = FileLength;
        }
        if ( bHasPassedAlotOfChecksWtf )
        {
          EAC::Memory::CopyUnicodeStringToAnsiBuffer(&pOutputStruct[1].gap1[239], 256i64, &v2[1].Length);
          if ( !RtlCompareUnicodeString(v2 + 1, v2, 0) )
            pOutputStruct->byte101 = 1;
          if ( v2 )
          {
            v23 = v2->Buffer;
            if ( v23 )
            {
              EAC::Memory::ExFreePool(v23);
              *v2 = 0i64;
            }
            EAC::Memory::FreeUnicdeString(&v2[1]);
            EAC::Memory::ExFreePool(v2);
          }
        }
      }
      Size2 = Size;
      v25 = EAC::Memory::GetImageBase(pCurrentFileBeingReadInMemory, Size);
      v26 = v25;
      if ( v25 )
      {
        Magic = v25->OptionalHeader.Magic;
        bHasPassedAlotOfChecksWtf = 1;
        if ( Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
          nImageArchitectureType = 32;
        else
          nImageArchitectureType = Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 0 : 64;
        pOutputStruct->nImageArchitectureType = nImageArchitectureType;
        EAC::Memory::memset(v46, 0, 0x200ui64);
        v29 = v46;
        LODWORD(v43) = 0;
        v42 = 0i64;
        if ( pCurrentFileBeingReadInMemory )
        {
          if ( Size >= 0x200 )
          {
            pDOSHeaders = EAC::Memory::GetImageBase(pCurrentFileBeingReadInMemory, Size);
            if ( pDOSHeaders )
            {
              while ( pDOSHeaders > pCurrentFileBeingReadInMemory )
              {
                pDOSHeaders = (pDOSHeaders - 4);
                if ( *&pDOSHeaders->e_magic == 'hciR' )
                {
                  if ( pDOSHeaders <= pCurrentFileBeingReadInMemory )
                    break;
                  v31 = *&pDOSHeaders->e_cp;
                  v32 = pDOSHeaders;
                  do
                  {
                    if ( pDOSHeaders <= pCurrentFileBeingReadInMemory )
                      goto BREAK_LABEL_MEME;
                    pDOSHeaders = (pDOSHeaders - 4);
                  }
                  while ( (*&pDOSHeaders->e_magic ^ v31) != 'SnaD' );
                  if ( pDOSHeaders <= pCurrentFileBeingReadInMemory
                    || *&pDOSHeaders->e_cp != v31
                    || *&pDOSHeaders->e_cparhdr != v31
                    || *&pDOSHeaders->e_maxalloc != v31
                    || (v33 = &pDOSHeaders->e_sp, (((v32 - v33) >> 2) - 2) > 0x7E) )
                  {
BREAK_LABEL_MEME:
                    Size2 = Size;
                    break;
                  }
                  while ( v33 < v32 )
                  {
                    v29->m128_i32[0] = *v33 ^ v31;
                    v29 = (v29 + 4);
                    v33 += 2;
                  }
                  EAC::HWID::HashVar(v46, v29 - v46, &v42);
                  nEndOfHash = (v31 ^ HIDWORD(v42) ^ DWORD1(v42)) << 32;
                  Size2 = Size;
                  nRichHeadersHash = v43 ^ DWORD2(v42) ^ v42 | nEndOfHash;
                  goto DONT_NULL_OUT_RICHHEADERS_VAR;
                }
              }
            }
          }
        }
        nRichHeadersHash = 0i64;
DONT_NULL_OUT_RICHHEADERS_VAR:
        bIs64Bit = pOutputStruct->nImageArchitectureType == 64;
        pOutputStruct->nRichHeadersHash = nRichHeadersHash;
        if ( bIs64Bit )
          pOutputStruct->nHashOfSomeWeirdShit = EAC::HWID::HashMoreFileShitNotSureWhat(
                                                  pCurrentFileBeingReadInMemory,
                                                  Size,
                                                  0);
        pOutputStruct->nImageAddressOfEntryPoint = v26->OptionalHeader.AddressOfEntryPoint;
        pOutputStruct->nImageSizeofCode = v26->OptionalHeader.SizeOfCode;
        LODWORD(v43) = 0;
        v42 = 0i64;
        if ( pCurrentFileBeingReadInMemory
          && Size >= 0x200
          && (pNTHeaders = EAC::Memory::GetImageBase(pCurrentFileBeingReadInMemory, Size2)) != 0i64 )
        {
          v37 = 0x78i64;
          if ( pNTHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            v37 = 0x88i64;
          EAC::HWID::HashVar(pNTHeaders + v37, 0x80u, &v42);
          nHash = ((HIDWORD(v42) ^ DWORD1(v42)) << 32) | v43 ^ DWORD2(v42) ^ v42;
        }
        else
        {
          nHash = 0i64;
        }
        pOutputStruct->nNTHeadersHash = nHash;
        EAC::HWID::SetNTOSKRNLOptionalHeaderHash(
          pCurrentFileBeingReadInMemory,
          Size,
          &pOutputStruct->nNTOSKRNLOptionalHash);
        pOutputStruct->nImageChecksum = v26->OptionalHeader.CheckSum;
        pOutputStruct->nImageSizeOf = v26->OptionalHeader.SizeOfImage;
        pOutputStruct->nImageTimeDateStamp = v26->FileHeader.TimeDateStamp;
      }
      else
      {
        bHasPassedAlotOfChecksWtf = 0;
      }
      pOutputStruct->ImageSize = Size;
      if ( pCurrentFileBeingReadInMemory )
        EAC::Memory::ExFreePool(pCurrentFileBeingReadInMemory);
    }
    EAC::Memory::FreeUnicdeString(&UNICODESTR);
  }
  return bHasPassedAlotOfChecksWtf;
}

unsigned __int64 __fastcall EAC::HWID::HashMoreFileShitNotSureWhat(unsigned __int64 a1, unsigned int a2, char a3)
{
  unsigned __int64 v5; // rbx
  unsigned __int64 result; // rax
  __int64 v7; // r15
  __int64 v8; // rax
  __int64 v9; // rdx
  unsigned int *v10; // rsi
  __int64 v11; // rax
  unsigned __int64 v12; // r14
  unsigned __int64 v13; // r9
  unsigned int *v14; // rcx
  unsigned int v15; // edx
  __int128 v16; // [rsp+30h] [rbp-38h] BYREF
  unsigned int v17; // [rsp+40h] [rbp-28h]

  v5 = 0i64;
  result = 0i64;
  v16 = 0i64;
  v17 = 0;
  if ( a1 && a2 )
  {
    v7 = a2;
    v8 = EAC::Memory::GetImageBase(a1, a2);
    if ( v8 && EAC::Memory::GetProcessArchitectureType(v8) == 64 )
    {
      v10 = (v9 + 144);
      if ( *(v9 + 24) != 267 )
        v10 = (v9 + 160);
      v11 = *v10;
      if ( v11 )
      {
        v12 = v10[1];
        if ( v12 )
        {
          v13 = a3 ? v11 + a1 : sub_14004EC8C(v11, v9, a1);
          if ( v13 >= a1 && v12 + v13 > v13 && v12 + v13 <= v7 + a1 && v12 == 12 * (v12 / 12) )
          {
            v14 = v13;
            v15 = 0;
            while ( v14 < v13 + 12 * (v12 / 12) )
            {
              if ( v15 > *v14 )
                goto LABEL_21;
              v15 = *v14;
              v14 += 3;
            }
            EAC::HWID::HashVar(v13, v12, &v16);
            v5 = v17 ^ DWORD2(v16) ^ v16 | ((HIDWORD(v16) ^ DWORD1(v16) ^ v10[1]) << 32);
          }
        }
      }
    }
LABEL_21:
    result = v5;
  }
  return result;
}
