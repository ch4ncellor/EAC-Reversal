char EAC::Callbacks::SomeDriverChecks()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  pOutputResult = 0;
  v14 = -5772;
  pCheckDriverDispatch = 0;
  v13[0] = -683422989;
  v15[0] = 0i64;
  v1 = 0i64;
  LOWORD(v15[1]) = 0;
  v2 = -685061481;
  v13[1] = -2105495067;
  v21 = v13;
  v22 = v15;
  v3 = 8i64;
  do
  {
    *(v22 + v1 * 4) = v21[v1] ^ v2;
    ++v1;
    v2 = __ROL4__(((v2 ^ (v2 << 13)) >> 17) ^ v2 ^ (v2 << 13) ^ (32 * (((v2 ^ (v2 << 13)) >> 17) ^ v2 ^ (v2 << 13))), 1);
  }
  while ( v1 < 2 );
  v21 = v13;
  v22 = v15;
  do
  {
    v4 = v2;
    v2 >>= 8;
    *(v22 + v3) = *(v21 + v3) ^ v4;
    ++v3;
  }
  while ( v3 < 0xA );
  EAC::Memory::memset(&nDriverCTLMinusAddress, 0, 0x108ui64);
  EAC::Memory::InitializeUnicodeStringWithCString(v16, v15);
  pDriverObject = EAC::Memory::GetDriverObject(v16);
  pDriverObject_1 = pDriverObject;
  if ( pDriverObject )
  {
    pCheckDriverDispatch = EAC::Callbacks::CheckDriverDispatch(
                             pDriverObject,
                             v6,
                             &nDriverCTLMinusAddress,
                             &pOutputResult);
    ObfDereferenceObject(pDriverObject_1);
    nDetectionResult = pOutputResult;
  }
  else
  {
    nDetectionResult = 1;
  }
  for ( i = 0i64; i < 256; ++i )
  {
    if ( !a3_8[i] )
      break;
  }
  pAllocated = EAC::Memory::ExAllocatePoolWithRandomTag2(i + 0xA);
  pAllocated_1 = pAllocated;
  if ( pAllocated )                             // send driver information to server aswell?
  {
    EAC::Memory::memset(pAllocated, 0, i + 0xA);
    pAllocated_1->nDriverCTLMinusAddress = nDriverCTLMinusAddress;
    pAllocated_1->dword5 = a3_4;
    pAllocated_1->nDetectionResult = nDetectionResult;
    if ( i )
      EAC::Memory::memmove(&pAllocated_1->oword9, a3_8, i);
    if ( i != 0xFFFFFFFFFFFFFFF6ui64 )
    {
      EAC::Callbacks::ReportViolation(0x125F58F6i64, pAllocated_1, (i + 0xA));
FREE_POOL_LABEL:
      EAC::Memory::ExFreePool(pAllocated_1);
      goto END_RET_LABEL;
    }
  }
  EAC::Callbacks::ReportViolation(0x125F58F6i64, 0i64, 0i64);
  if ( pAllocated_1 )
    goto FREE_POOL_LABEL;
END_RET_LABEL:
  memset(v15, 0, 0xAui64);
  return pCheckDriverDispatch;
}

char __fastcall EAC::Callbacks::CheckDriverDispatch(_DRIVER_OBJECT *pDriverObject, __int64 a2, struct_a3 *a3, _DWORD *pOutDetectionResult)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  bIsOutsideDriverBounds = 0;
  if ( !pDriverObject )
  {
    if ( pOutDetectionResult )
      *pOutDetectionResult = 2;
    return 0;
  }
  pAddressOfDeviceCTLMJ = pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
  if ( !pAddressOfDeviceCTLMJ )
  {
    if ( pOutDetectionResult )
      *pOutDetectionResult = 4;
    return 0;
  }
  v8 = EAC::Memory::GetRunningModules();
  v9 = v8;
  if ( !v8 )
  {
    if ( pOutDetectionResult )
      *pOutDetectionResult = 5;
    return 0;
  }
  v11 = 0;
  if ( *v8 )
  {
    while ( 1 )
    {
      v12 = 0x128i64 * v11;
      nAddrOfModule = *(v12 + v8 + 24);
      if ( nAddrOfModule >= MmSystemRangeStart
        && pAddressOfDeviceCTLMJ >= nAddrOfModule
        && pAddressOfDeviceCTLMJ <= nAddrOfModule + *(v12 + v8 + 32) )
      {
        break;
      }
      if ( ++v11 >= *v8 )                       // driver majorfunction was in bounds, we can just leave now.
        goto GOTO_END_OF_FN;
    }
    bIsOutsideDriverBounds = 1;
    if ( a3 )
    {
      v14 = 0i64;
      a3->dword0 = pAddressOfDeviceCTLMJ - nAddrOfModule;
      v15 = &v9[v12 + 48];
      if ( !v15 )
        goto LABEL_34;
      do
      {
        if ( !*(v15 + v14) )
          break;
        ++v14;
      }
      while ( v14 < 0x100 );
      v16 = 0xFFi64;
      if ( v14 < 0xFF )
      {
LABEL_34:
        v16 = 0i64;
        if ( v15 )
        {
          do
          {
            if ( !*(v15 + v16) )
              break;
            ++v16;
          }
          while ( v16 < 0x100 );
        }
      }
      EAC::Memory::memmove(&a3->oword8, v15, v16);
      *(&a3->oword8 + v16) = 0;
      a3->dword4 = *&v9[v12 + 32];
    }
    if ( pOutDetectionResult )
      *pOutDetectionResult = 7;
  }
GOTO_END_OF_FN:
  EAC::Memory::ExFreePool(v9);
  if ( !bIsOutsideDriverBounds && pOutDetectionResult )
    *pOutDetectionResult = 6;
  return bIsOutsideDriverBounds;
}

__int64 __fastcall EAC::Callbacks::DetectProcessHackerDriver(unsigned __int64 a1, __int64 a2)
{
  unsigned __int64 v3; // rsi
  unsigned __int8 *v4; // rdi
  unsigned __int64 v5; // rsi
  unsigned __int64 v6; // rbp
  bool i; // cf
  ULONG nTimeStamp; // ecx
  unsigned int v10; // [rsp+40h] [rbp+8h] BYREF
  IMAGE_NT_HEADERS64 *pImage; // [rsp+48h] [rbp+10h] BYREF

  v10 = 0;
  v3 = a2 & 0xFFFFFFFFFFFFF000ui64;
  if ( a1 < MmSystemRangeStart
    || (a1 & 0xFFFFFFFFFFFFF000ui64) != a1
    || !v3
    || ((qword_140073200 ^ a1) & 0xFFFFFFFF00000000ui64) != 0 )
  {
    return 0i64;
  }
  v4 = EAC::Memory::ExAllocatePoolWithRandomTag2(4096i64);
  if ( v4 )
  {
    v5 = a1 + v3;
    v6 = a1;
    for ( i = a1 < v5; i && !v10; i = v6 < v5 )
    {
      if ( EAC::Imports::MmCopyMemory(v6, 0x1000ui64, v4) == 4096 )
      {
        sub_14000F6DC(v4, 4096i64, sub_14003F8D8, &v10);
        if ( v6 == a1 )
        {
          if ( EAC::Memory::GetPEHeader(v4, 0x1000ui64, 0i64, &pImage) )
          {
            if ( pImage->FileHeader.NumberOfSections == 7
              && pImage->OptionalHeader.AddressOfEntryPoint == 0x9064
              && pImage->OptionalHeader.SizeOfImage == 0xB000 )
            {
              nTimeStamp = pImage->FileHeader.TimeDateStamp;
              if ( nTimeStamp == 0x56F975FA || nTimeStamp == 0x57089DA8 )
              {
                v10 = 0;
                break;
              }
            }
          }
          if ( !v10 )
            v10 = sub_14003FBB4(v4);
        }
      }
      v6 += 4096i64;
    }
    EAC::Memory::ExFreePool(v4);
  }
  return v10;
}

__int64 __fastcall EAC::Callbacks::FindProcessHackerDriverFile(_FLT_CALLBACK_DATA *a1, __int64 a2)
{
  unsigned int v4; // ebx
  PFLT_IO_PARAMETER_BLOCK v5; // rdx
  SIZE_T v6; // rsi
  PVOID v7; // r14
  PFLT_IO_PARAMETER_BLOCK v8; // rdx
  __int128 FileInformation; // [rsp+50h] [rbp-38h] BYREF
  __int64 v11; // [rsp+60h] [rbp-28h]
  ULONG LengthReturned; // [rsp+90h] [rbp+8h] BYREF
  union _LARGE_INTEGER ByteOffset; // [rsp+A8h] [rbp+20h] BYREF

  v11 = 0i64;
  v4 = 1;
  FileInformation = 0i64;
  if ( a1 )
  {
    if ( a2 )
    {
      if ( a1->Iopb->MajorFunction == 255 && !KeGetCurrentIrql() && FltGetRequestorProcess(a1) == PsInitialSystemProcess )
      {
        v5 = a1->Iopb;
        if ( v5->Parameters.Read.Length == 1
          && (v5->Parameters.AcquireForSectionSynchronization.PageProtection & 0xF0) != 0
          && FltQueryInformationFile(
               *(a2 + 24),
               v5->TargetFileObject,
               &FileInformation,
               0x18u,
               FileStandardInformation,
               &LengthReturned) >= 0
          && LengthReturned == 24 )
        {
          v6 = *(&FileInformation + 1);
          if ( *(&FileInformation + 1) <= 0xFFFFFFFFi64 )
          {
            if ( *(&FileInformation + 1) > 0x800000 )
              v6 = 0x800000i64;
            v7 = FltAllocatePoolAlignedWithTag(*(a2 + 24), NonPagedPool, v6, 'godW');
            if ( v7 )
            {
              v8 = a1->Iopb;
              ByteOffset.QuadPart = 0i64;
              if ( FltReadFile(*(a2 + 24), v8->TargetFileObject, &ByteOffset, v6, v7, 4u, &LengthReturned, 0i64, 0i64) >= 0
                && EAC::Callbacks::IsFileProcessHackerDriver(v7, LengthReturned) )
              {
                a1->IoStatus.Status = 0xC0000022;
                v4 = 4;
              }
              FltFreePoolAlignedWithTag(*(a2 + 24), v7, 'godW');
            }
          }
        }
      }
    }
  }
  return v4;
}

__int64 __fastcall EAC::Callbacks::IsFileProcessHackerDriver(unsigned __int8 *a1, unsigned __int64 a2)
{
  __int64 v4; // rcx
  __int64 result; // rax
  ULONG v6; // ecx
  unsigned int v7; // [rsp+30h] [rbp+8h] BYREF
  IMAGE_NT_HEADERS64 *v8; // [rsp+40h] [rbp+18h] BYREF

  v7 = 0;
  if ( !a1 || !a2 )
    return 0i64;
  sub_14000F6DC(a1, a2, sub_14003F8D8, &v7);
  result = v7;
  if ( !v7 )
  {
    result = EAC::Memory::IncreaseImageSizeWeird(v4, a1, a2);
    v7 = result;
    if ( !result )
    {
      result = sub_14003FE78(a1, a2);
      v7 = result;
    }
  }
  if ( result == 9 )
  {
    if ( !EAC::Memory::GetPEHeader(a1, 0x1000ui64, 0i64, &v8) )
      return v7;
    if ( v8->FileHeader.NumberOfSections != 7 )
      return v7;
    if ( v8->OptionalHeader.AddressOfEntryPoint != 0x9064 )
      return v7;
    if ( v8->OptionalHeader.SizeOfImage != 0xB000 )
      return v7;
    v6 = v8->FileHeader.TimeDateStamp;
    if ( v6 != 0x56F975FA && v6 != 0x57089DA8 )
      return v7;
    return 0i64;
  }
  return result;
}

__int64 __fastcall EAC::Callbacks::MoreDriverChecks(_OWORD *a1)
{
  unsigned int v2; // ebx
  unsigned int *v3; // rax
  unsigned int *v4; // rsi
  unsigned int v5; // ebp
  __int64 v6; // rdi
  unsigned __int64 v7; // rax
  char *v8; // rdx
  unsigned __int64 v9; // r8
  unsigned __int64 v10; // rcx
  __int64 v11; // r8
  char v12; // dl
  _BYTE *v13; // rax
  __int64 v14; // rcx

  v2 = 0;
  KeQueryTimeIncrement();
  v3 = EAC::Memory::GetRunningModules();
  v4 = v3;
  if ( !v3 )
    goto LABEL_35;
  v5 = 0;
  if ( *v3 )
  {
    do
    {
      if ( v2 )
        break;
      v6 = &v4[74 * v5 + 2];
      v2 = EAC::Callbacks::DetectProcessHackerDriver(*(v6 + 16), *(v6 + 24));
      if ( v2 || (v2 = EAC::Memory::GetSomeFilePEHeaderInfo(v6), v2 != 22) )
      {
        if ( v2 == 5 )
        {
          v10 = 0i64;
          v11 = v6 + *(v6 + 38);
          v12 = *(v11 + 40);
          v13 = (v11 + 40);
          if ( v12 )
          {
            do
            {
              ++v13;
              ++v10;
            }
            while ( *v13 );
            if ( v10 >= 16 && v12 == 'p' )
            {
              v14 = 1i64;
              while ( (*(v14 + v11 + 40) - 48) <= 9u )
              {
                if ( ++v14 >= 12 )
                {
                  v2 = 0;
                  break;
                }
              }
            }
          }
        }
      }
      else if ( v6 != 0xFFFFFFFFFFFFFFD8ui64 && a1 )
      {
        v7 = 0i64;
        v8 = (v6 + *(v6 + 38) + 40i64);
        if ( v8 )
        {
          while ( v8[v7] )
          {
            if ( ++v7 >= 256 )
            {
              if ( v7 < 0x104 )
                break;
              v9 = 260i64;
              goto LABEL_16;
            }
          }
        }
        v9 = 0i64;
        if ( v8 )
        {
          do
          {
            if ( !v8[v9] )
              break;
            ++v9;
          }
          while ( v9 < 0x100 );
        }
LABEL_16:
        EAC::Memory::memmove(a1, v8, v9);
      }
      ++v5;
    }
    while ( v5 < *v4 );
  }
  EAC::Memory::ExFreePool(v4);
  if ( !v2 )
  {
LABEL_35:
    if ( EAC::Callbacks::CheckForBlacklistedDriverNames() )
    {
      v2 = 18;
    }
    else if ( EAC::Callbacks::GetDriverAttributesFileList() )
    {
      v2 = 7;
    }
  }
  return v2;
}

__int64 __fastcall EAC::Callbacks::AddDriverHashToServerList(__int64 BaseAddress, unsigned __int64 ImageLength, __int64 DriverInstance, __int64 *ChangedPartList, _DWORD *a5)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v31 = ImageLength;
  v30 = BaseAddress;
  v7 = ImageLength;
  v8 = BaseAddress;
  v9 = -1073741271;
  if ( !KeGetCurrentIrql() )
  {
    if ( BaseAddress )
    {
      if ( ImageLength )
      {
        if ( DriverInstance )
        {
          v10 = *(DriverInstance + 16);
          if ( v10 )
          {
            if ( *(DriverInstance + 24)
              && v10 >= MmSystemRangeStart
              && ChangedPartList
              && a5
              && EAC::Memory::IsWithinMemoryConstraint(DriverInstance, v8)
              && EAC::Memory::IsWithinMemoryConstraint(v11, v8 + v7) )
            {
              *ChangedPartList = 0i64;
              *a5 = 0;
              v12 = EAC::Memory::ExAllocatePoolWithRandomTag2(8 * (v7 >> 12) + 8);
              *ChangedPartList = v12;
              if ( !v12 )
                return v9;
              if ( KeGetCurrentIrql() <= 1u )
              {
                ExAcquireFastMutex(&stru_1400732D0);
                if ( !EAC::Memory::HashDatabaseAllocated && !EAC::Globals::HasInitHash )
                {
                  v13 = EAC::Memory::ExAllocatePoolWithRandomTag2(24576i64);
                  EAC::Memory::HashDatabase = v13;
                  if ( v13 )
                  {
                    EAC::Memory::HashDatabaseAllocated = 1;
                    memset(v13, 0, 0x6000ui64);
                  }
                }
                ExReleaseFastMutex(&stru_1400732D0);
                if ( EAC::Memory::HashDatabaseAllocated )
                {
                  v14 = EAC::Memory::CRC32((DriverInstance + 40), 0x100u, 0);
                  driverHash = 0i64;
                  ExAcquireFastMutex(&stru_1400732D0);
                  if ( EAC::Memory::HashDatabaseAllocated )
                  {
                    v16 = 0i64;
                    if ( EAC::Memory::NumberOfBytes )
                    {
                      v17 = EAC::Memory::HashDatabase + 4;
                      while ( *v17 != v14 )
                      {
                        ++v16;
                        v17 += 6;
                        if ( v16 >= EAC::Memory::NumberOfBytes )
                          goto LABEL_32;
                      }
                      driverHash = EAC::Memory::ExAllocatePoolWithRandomTag2(24i64);
                      if ( driverHash )
                      {
                        v18 = EAC::Memory::HashDatabase;
                        v19 = 3 * v16;
                        *driverHash = *(EAC::Memory::HashDatabase + 8 * v19);
                        *(driverHash + 16) = v18[v19 + 2];
                        v20 = EAC::Memory::ExAllocatePoolWithRandomTag2(4i64 * HIDWORD(v18[v19 + 1]));
                        *(driverHash + 16) = v20;
                        if ( v20 )
                        {
                          EAC::Memory::memmove(
                            v20,
                            *(EAC::Memory::HashDatabase + v19 + 2),
                            4i64 * *(EAC::Memory::HashDatabase + 2 * v19 + 3));
                          if ( *(driverHash + 12) )
                          {
                            v21 = 0i64;
                            do
                            {
                              *(*(driverHash + 16) + 4 * v21) ^= *driverHash;
                              v21 = (v21 + 1);
                            }
                            while ( v21 < *(driverHash + 12) );
                          }
                        }
                        else
                        {
                          EAC::Memory::ExFreePool(driverHash);
                          driverHash = 0i64;
                        }
                      }
                    }
                  }
LABEL_32:
                  ExReleaseFastMutex(&stru_1400732D0);
                  if ( driverHash )
                  {
LABEL_43:
                    v27 = EAC::Memory::GetDriverHash(driverHash, v8, v7, *(DriverInstance + 16), ChangedPartList, a5);
                    v28 = *(driverHash + 16);
                    v9 = v27 == 0 ? 0xC0000005 : 0;
                    if ( v28 )
                      EAC::Memory::ExFreePool(v28);
                    EAC::Memory::ExFreePool(driverHash);
                    if ( (v9 & 0x80000000) == 0 && *a5 )
                      return v9;
                    goto LABEL_47;
                  }
                  driverHash = EAC::Memory::HashDriver(v14, DriverInstance);
                  if ( driverHash )
                  {
                    ExAcquireFastMutex(&stru_1400732D0);
                    if ( EAC::Memory::HashDatabaseAllocated && EAC::Memory::NumberOfBytes < 1024 )
                    {
                      v22 = EAC::Memory::HashDatabase;
                      v23 = 3i64 * EAC::Memory::NumberOfBytes;
                      *(EAC::Memory::HashDatabase + 8 * v23) = *driverHash;
                      v22[v23 + 2] = *(driverHash + 16);
                      v24 = EAC::Memory::ExAllocatePoolWithRandomTag2(4i64 * *(driverHash + 12));
                      v25 = EAC::Memory::NumberOfBytes;
                      *(EAC::Memory::HashDatabase + 3 * EAC::Memory::NumberOfBytes + 2) = v24;
                      if ( v24 )
                      {
                        EAC::Memory::memmove(v24, *(driverHash + 16), 4i64 * *(driverHash + 12));
                        if ( HIDWORD(v22[v23 + 1]) )
                        {
                          v26 = 0i64;
                          do
                          {
                            *(v22[v23 + 2] + 4 * v26) ^= LODWORD(v22[v23]);
                            v26 = (v26 + 1);
                          }
                          while ( v26 < HIDWORD(v22[v23 + 1]) );
                        }
                        EAC::Memory::NumberOfBytes = v25 + 1;
                      }
                      v8 = v30;
                      v7 = v31;
                    }
                    ExReleaseFastMutex(&stru_1400732D0);
                    goto LABEL_43;
                  }
                  v9 = 0xC0000123;
                }
              }
LABEL_47:
              EAC::Memory::ExFreePool(*ChangedPartList);
              return v9;
            }
          }
        }
      }
    }
  }
  return 0xC000000Di64;
}

_QWORD *__fastcall EAC::Memory::HashDriver(int a1, __int64 a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v2 = *(a2 + 40);
  v37 = 0;
  v3 = *(a2 + 56);
  v4 = 0i64;
  v32[0] = v2;
  v7 = *(a2 + 72);
  v32[1] = v3;
  v8 = *(a2 + 88);
  v32[2] = v7;
  v9 = *(a2 + 104);
  v32[3] = v8;
  v10 = *(a2 + 120);
  v32[4] = v9;
  v11 = *(a2 + 136);
  v32[5] = v10;
  v32[6] = v11;
  v32[7] = *(a2 + 152);
  v12 = *(a2 + 280);
  v13 = *(a2 + 184);
  v32[8] = *(a2 + 168);
  v14 = *(a2 + 200);
  v32[9] = v13;
  v15 = *(a2 + 216);
  v32[10] = v14;
  v16 = *(a2 + 232);
  v32[11] = v15;
  v17 = *(a2 + 248);
  v32[12] = v16;
  v18 = *(a2 + 264);
  v32[13] = v17;
  v32[14] = v18;
  v33 = v12;
  v34 = *(a2 + 288);
  v35 = *(a2 + 292);
  v36 = *(a2 + 294);
  v30[1] = v32;
  v19 = -1i64;
  do
    ++v19;
  while ( *(v32 + v19) );
  LOWORD(v30[0]) = v19;
  WORD1(v30[0]) = v19 + 1;
  if ( EAC::Memory::CreateUnicodeString(v31, v30) >= 0 )
  {
    v20 = EAC::Memory::IsFileValidPEImage(v31, *(a2 + 16), &v38, 1);
    v21 = v20;
    if ( v20 )
    {
      v22 = 0i64;
      v23 = EAC::Memory::GetSectionSize(v20);
      v24 = v38 % v23;
      v25 = v38 / v23;
      if ( v38 / v23 )
      {
        v22 = EAC::Memory::ExAllocatePoolWithRandomTag2(24i64);
        if ( v22 )
        {
          v26 = EAC::Memory::ExAllocatePoolWithRandomTag2(4i64 * v25);
          v22[2] = v26;
          if ( v26 )
          {
            *(v22 + 1) = a1;
            *v22 = EAC::Memory::GenerateSeed(0, -1);
            *(v22 + 2) = v23;
            *(v22 + 3) = v25;
            do
            {
              v27 = EAC::Memory::CRC32(&v21[v23 * v4], v23, 0);
              LODWORD(v4) = v4 + 1;
              *(v28 + v22[2]) = v27;
            }
            while ( v4 < v25 );
          }
          else
          {
            EAC::Memory::ExFreePool(v22);
            v22 = 0i64;
          }
        }
      }
      v4 = v22;
      sub_14003CCAC(v21, v24);
    }
    EAC::Memory::FreeUnicdeString(v31);
  }
  return v4;
}

LONG_PTR __fastcall EAC::Callbacks::ScanForKernelPatches(__int64 a1, __int64 a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v4 = 0;
  m_bHasNTOSKrnlBeenPatched = EAC::Callbacks::CheckForNTOSKRNLPatches() - 1;
  if ( !m_bHasNTOSKrnlBeenPatched )
  {
    v4 = 0xC0020007;
    goto LABEL_35;
  }
  if ( m_bHasNTOSKrnlBeenPatched == 1 )
  {
    v4 = 0xC0020008;
    goto LABEL_35;
  }
  if ( MEMORY[0xFFFFF7800000026C] <= 6u && (MEMORY[0xFFFFF7800000026C] != 6 || (MEMORY[0xFFFFF78000000270] - 2) > 1) )
    goto LABEL_28;
  if ( !EAC::Memory::GetBootGUID(v38, v41) )
  {
    EAC::Callbacks::ReportViolation_1(a2, 0x5AADB103i64, 0i64, 0i64, 0i64);
LABEL_28:
    sub_14002F998(a2, 0x40010006i64);
    v4 = sub_14004D884(a1, a2);
    goto LABEL_29;
  }
  if ( v39 )
  {
    strcpy(v23, "5Ê\\\x1Bê8L");
    *&v44[48] = 0i64;
    *&v44[56] = 0;
    v6 = -1286774945;
    v24 = 80942024;
    v7 = 0i64;
    v25 = 594688901;
    v26 = -299880827;
    v27 = -1561828364;
    v28 = -1767145028;
    v29 = -1192192300;
    v30 = -526128710;
    v31 = 1008280262;
    v32 = -1032869015;
    v33 = 1233558148;
    v34 = -2057461693;
    v35 = 1825154181;
    v36 = -2016214440;
    *v44 = 0i64;
    *&v44[16] = 0i64;
    *&v44[32] = 0i64;
    do
    {
      v6 = __ROL4__(214013 * v6 + 2531011, 4);
      *&v44[v7] = *&v23[v7] ^ v6;
      v7 += 4i64;
    }
    while ( v7 < 0x3C );
    v8 = 1;
    if ( !EAC::Memory::CompareUnicodeStr(v38, v44) )
      goto LABEL_15;
    v37[0] = 1666580416;
    *&v43[48] = 0i64;
    *&v43[56] = 0;
    v9 = -1709524677;
    v37[1] = -1558651321;
    v37[2] = 629101256;
    v10 = 0i64;
    v37[3] = 467525598;
    v37[4] = -1984057362;
    v37[5] = 736416474;
    v37[6] = -1549857426;
    v37[7] = -1801439344;
    v37[8] = 431986060;
    v37[9] = -1755171940;
    v37[10] = -958271565;
    v37[11] = 1854764083;
    v37[12] = -693829820;
    v37[13] = -1894837076;
    v37[14] = 529568623;
    *v43 = 0i64;
    *&v43[16] = 0i64;
    *&v43[32] = 0i64;
    do
    {
      v9 = __ROL4__(((v9 ^ (v9 >> 7)) << 9) ^ v9 ^ (v9 >> 7) ^ ((((v9 ^ (v9 >> 7)) << 9) ^ v9 ^ (v9 >> 7)) >> 13), 4);
      *&v43[v10 * 4] = v37[v10] ^ v9;
      ++v10;
    }
    while ( v10 < 15 );
    v8 = 3;
    if ( EAC::Memory::CompareUnicodeStr(v38, v43) )
    {
      LOBYTE(v4) = 1;
    }
    else
    {
LABEL_15:
      if ( (v8 & 2) == 0 )
      {
LABEL_17:
        memset(v44, 0, sizeof(v44));
        EAC::Memory::FreeUnicdeString(v38);
        v4 = v4 != 0 ? 0xC0020010 : 0;
        goto LABEL_18;
      }
    }
    memset(v43, 0, sizeof(v43));
    goto LABEL_17;
  }
LABEL_18:
  if ( v42 )
  {
    v21[0] = -437452254;
    v22 = 25715;
    v21[1] = 991072209;
    *&v40[1] = 0i64;
    v11 = 0i64;
    WORD4(v40[1]) = 0;
    v12 = -442957236;
    v21[2] = 55889785;
    v21[3] = 1113584501;
    v21[4] = -1296637238;
    v13 = 24i64;
    v21[5] = 799280214;
    v40[0] = 0i64;
    do
    {
      v14 = v21[v11] ^ v12;
      v12 = __ROL4__(1140671485 * v12 + 12820163, 1);
      *(v40 + v11 * 4) = v14;
      ++v11;
    }
    while ( v11 < 6 );
    do
    {
      v15 = v12;
      v12 >>= 8;
      *(v40 + v13) = *(v21 + v13) ^ v15;
      ++v13;
    }
    while ( v13 < 0x1A );
    v16 = EAC::Memory::CompareUnicodeStr(v41, v40);
    memset(v40, 0, 0x1Aui64);
    if ( v16 )
      v4 = 0xC0020011;
    EAC::Memory::FreeUnicdeString(v41);
  }
  if ( !v4 )
    goto LABEL_28;
LABEL_29:
  if ( v4 != 0x40031000 )
  {
LABEL_35:
    v19 = v4;
    v18 = a2;
    goto LABEL_36;
  }
  sub_140025304(a2);
  v17 = sub_140009F70(a2);
  v18 = a2;
  if ( !v17 )
  {
    v19 = 3221356569i64;
LABEL_36:
    EAC::Callbacks::ReportViolation_0(v18, v19);
    return sub_140027958();
  }
  sub_14002F6A8(a2, 0x40031000);
  return sub_140027958();
}

__int64 EAC::Callbacks::CheckForNTOSKRNLPatches()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v0 = 0i64;
  LODWORD(FileSize) = 0;
  v1 = 2;
  ntoskrnlBase = EAC::Memory::GetNTOSKRNLBaseAddress();
  if ( ntoskrnlBase && EAC::Memory::GetNTOSKRNLPath(ModulePath, 1) )
  {
    if ( MEMORY[0xFFFFF7800000026C] <= 6u && (MEMORY[0xFFFFF7800000026C] != 6 || (MEMORY[0xFFFFF78000000270] - 2) > 1) )
      goto LABEL_10;
    v7[0] = 1035157922;
    v7[1] = -1211973253;
    v7[2] = 890527115;
    v7[3] = -1604919530;
    v7[4] = 335976341;
    v7[5] = 768738782;
    v7[6] = 1965411501;
    v7[7] = 387677515;
    v7[8] = -584117672;
    v7[9] = 323241621;
    v7[10] = -1563280376;
    v7[11] = 2025074343;
    v7[12] = 2050208706;
    v7[13] = 239808795;
    v7[14] = 1411383000;
    v7[15] = -198881325;
    v7[16] = 331163443;
    EAC::Memory::memset(Dst, 0, 0x44ui64);
    v3 = 276658416;
    v13 = v7;
    v14 = Dst;
    do
    {
      v3 = ~(((v3 ^ (v3 << 13)) >> 7) ^ v3 ^ (v3 << 13) ^ ((((v3 ^ (v3 << 13)) >> 7) ^ v3 ^ (v3 << 13)) << 17));
      *(v14->m128_i32 + v0) = *(v13 + v0) ^ v3;
      v0 += 4i64;
    }
    while ( v0 < 0x44 );
    LOBYTE(v0) = 1;
    if ( EAC::Memory::CompareUnicodeStr(ModulePath, Dst) )// ntoskrnl.exe
    {
      v4 = 1;
    }
    else
    {
LABEL_10:
      v4 = 0;
      if ( (v0 & 1) == 0 )
        goto LABEL_13;
    }
    memset(Dst, 0, 0x44ui64);
    if ( v4 )
    {
      v1 = 1;
LABEL_26:
      EAC::Memory::FreeUnicdeString(ModulePath);
      return v1;
    }
LABEL_13:
    if ( EAC::Memory::ForceReadFile(ModulePath, &pAllocatedHeap, &FileSize) )
    {
      pAllocatedHeapAddr = pAllocatedHeap;
      if ( FileSize >= 0x1000 )
        v1 = !EAC::Memory::GetPEHeader(ntoskrnlBase, 0x1000ui64, &FileSize, &MemoryHeader)
          || !EAC::Memory::GetPEHeader(pAllocatedHeapAddr, 0x1000ui64, &FileSize, &DiskHeader)
          || MemoryHeader->FileHeader.NumberOfSections != DiskHeader->FileHeader.NumberOfSections
          || MemoryHeader->FileHeader.TimeDateStamp != DiskHeader->FileHeader.TimeDateStamp
          || MemoryHeader->OptionalHeader.AddressOfEntryPoint != DiskHeader->OptionalHeader.AddressOfEntryPoint
          || MemoryHeader->OptionalHeader.CheckSum != DiskHeader->OptionalHeader.CheckSum
          || MemoryHeader->OptionalHeader.SizeOfImage != DiskHeader->OptionalHeader.SizeOfImage;
      if ( pAllocatedHeapAddr )
        EAC::Memory::ExFreePool(pAllocatedHeapAddr);
    }
    goto LABEL_26;
  }
  return v1;
}

