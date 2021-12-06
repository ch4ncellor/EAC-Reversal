bool __fastcall EAC::Callbacks::BeginWindowsInjection(__int64 a1)
{
  _UNICODE_STRING *v1; // r14
  bool v3; // bl
  char v4; // di
  unsigned int v5; // edx
  unsigned __int64 v6; // rdi
  unsigned __int64 i; // r8
  char v8; // cl
  int v9; // eax
  char v10; // dl
  __m128 *pBuffer; // rax
  __int64 v13; // rdx
  __m128 *v14; // rdi
  bool v15; // al
  int v16[21]; // [rsp+20h] [rbp-79h]
  __int16 v17; // [rsp+74h] [rbp-25h]
  char v18[122]; // [rsp+76h] [rbp-23h] BYREF

  v1 = (a1 + 16);
  v3 = 0;
  v4 = 0;
  if ( !EAC::Memory::ExAllocatePoolWithRandomTag2Wrapper(a1 + 16, 0x1000u) )
    goto LABEL_6;
  v16[0] = -1161486776;
  v17 = -7342;
  v16[1] = 2131784440;
  v16[2] = -1779023309;
  v16[3] = 1647530064;
  v16[4] = 883744188;
  v16[5] = 724101881;
  v16[6] = 2011759064;
  v16[7] = 496383216;
  v16[8] = -1184496954;
  v16[9] = 36685397;
  v16[10] = 930039539;
  v16[11] = -836592059;
  v16[12] = 1150566866;
  v16[13] = -919534435;
  v16[14] = 2032694796;
  v16[15] = 8270150;
  v16[16] = -1979060004;
  v16[17] = 771305898;
  v16[18] = -1362328921;
  v16[19] = -1669975869;
  v16[20] = 1112865952;
  EAC::Memory::memset(v18, 0, 0x56ui64);
  v5 = -1164567020;
  v6 = 84i64;
  for ( i = 0i64; i < 21; ++i )
  {
    *&v18[i * 4] = v16[i] ^ v5;
    v5 = __ROL4__(((v5 ^ (v5 << 13)) >> 7) ^ v5 ^ (v5 << 13) ^ ((((v5 ^ (v5 << 13)) >> 7) ^ v5 ^ (v5 << 13)) << 17), 4);
  }
  do
  {
    v8 = v5;
    v5 >>= 8;
    v18[v6] = *(v16 + v6) ^ v8;
    ++v6;
  }
  while ( v6 < 0x56 );
  v4 = 1;
  v9 = EAC::Memory::RtlUnicodeStringPrintf(v1, v18, __rdtsc());
  v10 = 0;
  if ( v9 < 0 )
LABEL_6:
    v10 = 1;
  if ( (v4 & 1) != 0 )
    memset(v18, 0, 0x56ui64);
  if ( v10 )
    return 0;
  pBuffer = EAC::Memory::GetImageBuffer(&unk_140066E90, 21992i64);
  v14 = pBuffer;
  if ( pBuffer )
  {
    if ( EAC::Memory::ForceWriteFile(v1, v13, pBuffer) )
    {
      *(a1 + 8) = 1;
      v15 = EAC::Callbacks::LoadLibraryInjection(a1, 1) >= 0;
      *(a1 + 9) = v15;
      v3 = v15;
    }
    EAC::Memory::memset(v14, 0, 0x55E8ui64);
    EAC::Memory::ExFreePool(v14);
  }
  return v3;
}

char __fastcall EAC::Callbacks::BeginWindowsInjectionWrapper(PVOID Object)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v1 = 0;
  v2 = 0;
  if ( !Object || !EAC::Globals::UnknownInjectionBoolean )
    goto LABEL_20;
  ExAcquireFastMutex(&stru_140073E70);
  v4 = 0i64;
  v5 = &EAC::Globals::LoadLibraryInjectionStruct;
  while ( *v5 != Object )
  {
    ++v4;
    v5 += 4;
    if ( v4 >= 0x10 )
    {
      v6 = 0i64;
      goto LABEL_7;
    }
  }
  v6 = &EAC::Globals::LoadLibraryInjectionStruct + 32 * v4;
  if ( v6 )
  {
    v1 = v6[9];
    v9 = v6;
    goto LABEL_15;
  }
LABEL_7:
  v7 = 0i64;
  v8 = &EAC::Globals::LoadLibraryInjectionStruct;
  while ( *v8 )
  {
    ++v7;
    v8 += 4;
    if ( v7 >= 0x10 )
    {
      v9 = 0i64;
      goto LABEL_14;
    }
  }
  v10 = 32 * v7;
  *(&EAC::Globals::LoadLibraryInjectionStruct + v10 + 8) = 0i64;
  v9 = &EAC::Globals::LoadLibraryInjectionStruct + v10;
  *(&EAC::Globals::LoadLibraryInjectionStruct + v10 + 16) = 0i64;
  *(&EAC::Globals::LoadLibraryInjectionStruct + v10 + 24) = 0i64;
  *(&EAC::Globals::LoadLibraryInjectionStruct + v10) = Object;
  if ( (&EAC::Globals::LoadLibraryInjectionStruct + v10) )
    goto LABEL_15;
LABEL_14:
  v2 = 1;
LABEL_15:
  ExReleaseFastMutex(&stru_140073E70);
  if ( v6 )
    return v1;
  if ( !v2 && (ObfReferenceObject(Object), EAC::Callbacks::BeginWindowsInjection(v9)) )
    result = 1;
  else
LABEL_20:
    result = 0;
  return result;
}

__int64 __fastcall EAC::Callbacks::LoadLibraryInjection(struct_a1_1 *pInputStruct, char a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v34 = a2;
  v4 = 0xC0000001;
  LODWORD(v18) = 0xC0000001;
  v25 = 0i64;
  if ( !sub_140021608(&pInputStruct->unsigned___int1610, &v26) )
    return 0xC000000Di64;
  if ( EAC::Callbacks::KeStackAttachProcess(pInputStruct->HANDLE, v32) )
  {
    v8 = EAC::Imports::NtAllocateVirtualMemoryWrapper(v6, 4096i64, v7, 64);
    v9 = v8;
    v25 = v8;
    if ( !v8 )
      goto FREE_MEMORY_AND_UNSTACK_LABEL;
    EAC::Memory::CheckAddressBounds(v8, 4096i64);
    *v9 = xmmword_14006C490;
    *(v9 + 16) = xmmword_14006C4A0;
    *(v9 + 32) = xmmword_14006C4B0;
    *(v9 + 48) = xmmword_14006C4C0;
    v23[0] = 183270618;
    v23[1] = -1577622027;
    v23[2] = 851333393;
    v23[3] = 212456202;
    v23[4] = 1264994537;
    v23[5] = -444005607;
    v24 = 17185;
    v10 = EAC::Memory::DecryptStr5(v23, v30);
    v11 = EAC::Callbacks::GetUsermodeModuleWrapper(v10);
    memset(v30, 0, 0x1Aui64);
    if ( !v11 )
      goto FREE_MEMORY_AND_UNSTACK_LABEL;
    if ( a2 )
    {
      v21[0] = 0x984BB8DA;
      v21[1] = -1983652296;
      v21[2] = -1640782585;
      v22 = 43;
      v12 = 1;
      str = EAC::Memory::DecryptStr3(v21, v29);
    }
    else
    {
      HIDWORD(v18) = 974224348;
      v19 = 1879373332;
      v20 = -573867558;
      v12 = 2;
      str = EAC::Memory::DecryptStr4(&v18 + 4, v28);
    }
    *(v9 + 64) = sub_14004F1A4(v14, str);
    if ( (v12 & 2) != 0 )
    {
      v12 &= 0xFDu;
      memset(v28, 0, sizeof(v28));
    }
    if ( (v12 & 1) != 0 )
      memset(v29, 0, 0xDui64);
    if ( !*(v9 + 64) )
      goto FREE_MEMORY_AND_UNSTACK_LABEL;
    if ( v34 )
    {
      *(v9 + 72) = v9 + 80;
      EAC::Memory::memmove((v9 + 80), v27, v26);
    }
    else if ( !sub_140007B70(v33, 64i64, &v26)
           || (v15 = EAC::Callbacks::GetUsermodeModuleWrapper(v33), (*(v9 + 72) = v15) == 0i64) )
    {
FREE_MEMORY_AND_UNSTACK_LABEL:
      if ( v9 )
        EAC::Imports::NtFreeVirtualMemoryWrapper(v9);
      EAC::Callbacks::KeUnstackDetachProcess(pInputStruct->HANDLE, v32);
      return v4;
    }
    if ( EAC::Globals::RtlCreateUserThread )
    {
      v16 = EAC::Globals::RtlCreateUserThread(-1i64, 0i64, 0i64, 0i64, 0i64, 0i64, v9, v9 + 64, &Handle, 0i64);
    }
    else
    {
      if ( !EAC::Globals::RtlCreateUserThreadAlternative )
      {
        v4 = 0xC0000002;
        LODWORD(v18) = 0xC0000002;
LABEL_24:
        if ( v4 >= 0 )
        {
          ZwWaitForSingleObject(Handle, 0, 0i64);
          v4 = EAC::Imports::NtQueryInformationThread(Handle, 0, v31, 0x30u);
          LODWORD(v18) = v4;
          if ( v4 >= 0 )
          {
            v17 = LOWORD(v31[0]) | 0xC0070000;
            if ( v31[0] <= 0 )
              v17 = v31[0];
            v4 = v31[0] != 0 ? v17 : 0;
            LODWORD(v18) = v4;
          }
          EAC::Imports::NtClose(Handle);
        }
        goto FREE_MEMORY_AND_UNSTACK_LABEL;
      }
      v16 = EAC::Globals::RtlCreateUserThreadAlternative(
              -1i64,
              0i64,
              0i64,
              0i64,
              0i64,
              0i64,
              0i64,
              v9,
              v9 + 64,
              &Handle,
              0i64,
              0i64,
              v18);
    }
    v4 = v16;
    LODWORD(v18) = v16;
    goto LABEL_24;
  }
  return v4;
}

__int64 EAC::Callbacks::WindowsInjectionNumber2()
{
  struct_a1_1 *pInputStruct; // rbx
  __int64 v1; // rdi
  __int64 result; // rax

  if ( EAC::Globals::UnknownInjectionBoolean )
  {
    pInputStruct = &EAC::Globals::LoadLibraryInjectionStruct;
    v1 = 16i64;
    do
    {
      if ( pInputStruct->HANDLE )
      {
        if ( pInputStruct->gap8[1] )
          EAC::Callbacks::LoadLibraryInjection(pInputStruct, 0);
        result = EAC::Callbacks::DeleteFileByString(pInputStruct);
      }
      pInputStruct = (pInputStruct + 32);
      --v1;
    }
    while ( v1 );
  }
  return result;
}

// Most credits to mm injection reversal goes to @Sinclairq.
__int64 __fastcall EAC::Callbacks::GatherShellcodeToMap(struct_a1 *pInputStruct, __int64 a2, __int64 a3)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  pOutputStruct = 0i64;
  if ( pInputStruct )
  {
    BaseAddress = EAC::Imports::NtAllocateVirtualMemoryWrapper(pInputStruct, 4096i64, a3, 64);
    pOutputStruct = BaseAddress;
    if ( BaseAddress )
    {
      EAC::Memory::CheckAddressBounds(BaseAddress, 4096i64);
      if ( pInputStruct->ImageType == 64 )
      {                                         // Thanks to @Sinclairq for convieniently writing the shellcode all neatly like this
        *v7 = EAC::Globals::ShellcodeBuffer64Bit;//                      0x48, 0x83, 0xEC, 0x28,        // SUB RSP, 0x28
                                                //                         0x4D, 0x31, 0xC0, // XOR R8, R8
                                                //                         0x48, 0x31, 0xD2, // XOR RDX, RDX
                                                //                         0x48, 0xFF, 0xC2, // INC RDX
                                                //                         0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0
                                                //                         0xFF, 0xD0,        // CALL RAX
                                                //                         0x48, 0x83, 0xC4, 0x28, // ADD RSP, 0x28
                                                //                         0xC3 // RETN
        v7[23] = -1;
        *&v7[15] = pInputStruct->DllEntryPoint;
        *pOutputStruct = *v7;
        *(pOutputStruct + 16) = *&v7[16];
        *(pOutputStruct + 24) = 0xC48348D0;
        *(pOutputStruct + 28) = 0xC328;
      }
      else
      {
        v8 = EAC::Globals::ShellcodeBuffer32Bit;//                         0x6A, 0x00,        // PUSH 0
                                                //                         0x6A, 0x01,        // PUSH 1
                                                //                         0xFF, 0x74, 0xE4, 0x0C, // PUSH [RSP+0xC]
                                                //                         0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0
                                                //                         0xFF, 0xD0,        // CALL EAX
                                                //                         0xC2, 0x04, 0x00 // RETN 4
        *(&v8 + 9) = pInputStruct->DllEntryPoint;
        *pOutputStruct = v8;
        *(pOutputStruct + 16) = 4;
      }
    }
  }
  return pOutputStruct;
}

char __fastcall EAC::Callbacks::StartManualMap(ULONG64 a1)
{
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax

  v2 = EAC::Imports::PsGetCurrentProcess();
  v3 = EAC::Imports::PsGetCurrentProcessID(v2);
  if ( !EAC::Globals::GameProcessID || v3 != EAC::Globals::GameProcessID )
    return 0;
  v4 = EAC::Imports::PsGetCurrentProcess();
  if ( a1 == EAC::Imports::GetProcessBaseAddress(v4) && !_InterlockedCompareExchange(&dword_140073D94, 1, 0) )
  {
    EAC::Callbacks::ManualMapImage();
    EAC::Callbacks::StoreImageDataForLaterValidation(a1);
    if ( Event )
      KeSetEvent(Event, 0, 0);
  }
  return 1;
}

void EAC::Callbacks::ManualMapImage()
{
  __m128 *pBuffer; // rdi
  bool v1; // bl
  ULONG_PTR RegionSize; // [rsp+50h] [rbp+8h] BYREF
  __int64 v3; // [rsp+58h] [rbp+10h] BYREF

  stru_140073DE8.Count = 1;
  stru_140073DE8.Owner = 0i64;
  stru_140073DE8.Contention = 0;
  KeInitializeEvent(&stru_140073DE8.Event, SynchronizationEvent, 0);
  EAC::Globals_BaseAddress = 0i64;
  RegionSize = 208128i64;
  if ( ZwAllocateVirtualMemory(0xFFFFFFFFFFFFFFFFi64, &EAC::Globals_BaseAddress, 0i64, &RegionSize, 0x3000u, 4u) >= 0 )
  {
    EAC::Callbacks::IsInUsermodeAddressSpace(EAC::Globals_BaseAddress, RegionSize, 1);
    EAC::Memory::memset(EAC::Globals_BaseAddress, 0, RegionSize);
    pBuffer = EAC::Memory::GetImageBuffer(&unk_140060E70, 24576i64);
    if ( pBuffer )
    {
      v1 = EAC::Callbacks::MapImage(
             pBuffer,
             0x6000ui64,
             &EAC::Globals_BaseAddressOfMappedModule,
             &v3,
             &EAC::Globals::EntryPointOfMappedModule,
             0i64,
             0i64);
      EAC::Memory::memset(pBuffer, 0, 0x6000ui64);
      EAC::Memory::ExFreePool(pBuffer);
      if ( v1 )
      {
        EAC::Memory::memset(EAC::Globals_BaseAddressOfMappedModule, 0, 0x1000ui64);
        EAC::Globals::StoredBaseAddressOfMappedModule = EAC::Globals_BaseAddressOfMappedModule;
      }
    }
  }
}

bool __fastcall EAC::Callbacks::MapImage(char *ImageBase, unsigned __int64 ImageSize, __int64 *MappedBase, _QWORD *MappedSize, _QWORD *MappedEntryPoint, _DWORD *ExceptionDirectory, _DWORD *ExceptionDirectorySize)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v7 = 0i64;
  v25 = 0i64;
  if ( !ImageBase || !ImageSize || !MappedBase || !MappedSize || !MappedEntryPoint )
    return 0;
  *MappedBase = 0i64;
  *MappedSize = 0i64;
  *MappedEntryPoint = 0i64;
  if ( ExceptionDirectory )
    *ExceptionDirectory = 0;
  if ( ExceptionDirectorySize )
    *ExceptionDirectorySize = 0;
  if ( EAC::Memory::GetPEHeader(ImageBase, ImageSize, &a3a, &v24) )
  {
    v8 = v24;
    v9 = v24->FileHeader.Machine;
    if ( v9 == 332 )
    {
      v10 = 32;
      v11 = v24->OptionalHeader.SizeOfImage;
      v22 = v11;
LABEL_18:
      v30 = v11;
      Buffer = EAC::Memory::ExAllocatePoolWithRandomTag2(v11);
      v7 = Buffer;
      v25 = Buffer;
      if ( Buffer )
      {
        EAC::Memory::memmove(Buffer, ImageBase, ImageSize);
        v13 = EAC::Memory::GenerateSeed(4, 16) << 12;
        LODWORD(v24) = v13;
        v26 = v13;
        Size = EAC::Memory::GenerateSeed(4, 16) << 12;
        v27 = Size;
        v14 = v11 + Size + v13;
        v16 = EAC::Imports::NtAllocateVirtualMemoryWrapper(v14, v14, v15, 4);
        v17 = v16;
        v28 = v16;
        if ( v16 )
        {
          if ( EAC::Imports::NtProtectVirtualMemoryWrapper(v16, v14, 64, v23) )
          {
            EAC::Callbacks::IsInUsermodeAddressSpace(v17, v13, 1);
            EAC::Callbacks::RandomizeRegion(v17, v13);
            if ( EAC::Imports::NtProtectVirtualMemoryWrapper(v17, v13, 32, v23) )
            {
              v18 = &v17[v22 + v13];
              EAC::Callbacks::IsInUsermodeAddressSpace(v18, Size, 1);
              EAC::Callbacks::RandomizeRegion(v18, Size);
              if ( EAC::Imports::NtProtectVirtualMemoryWrapper(v18, Size, 2, v23) )
              {
                v19 = &v17[v24];
                v28 = v19;
                v20 = &v7[*(a3a + 60)];
                v24 = v20;
                EAC::Callbacks::ResolveRelocations(v19, v7, v10, v20);
                if ( v10 == 64 )
                  *(v20 + 48) = v19;
                else
                  *(v20 + 52) = v19;
                if ( EAC::Callbacks::MapSections(v19, v7, v20) )
                {
                  EAC::Memory::CorrectSectionProtection(v19, v20);
                  *MappedBase = v19;
                  *MappedSize = v30;
                  *MappedEntryPoint = v19 + *(v20 + 40);
                }
              }
            }
          }
        }
      }
      goto END;
    }
    if ( v9 == 0x8664 )
    {
      v10 = 64;
      v11 = v24->OptionalHeader.SizeOfImage;
      v22 = v11;
      if ( ExceptionDirectory )
        *ExceptionDirectory = v24->OptionalHeader.DataDirectory[3].VirtualAddress;
      if ( ExceptionDirectorySize )
        *ExceptionDirectorySize = v8->OptionalHeader.DataDirectory[3].Size;
      goto LABEL_18;
    }
  }
END:
  if ( v7 )
    EAC::Memory::ExFreePool(v7);
  return *MappedEntryPoint != 0i64;
}

char __fastcall EAC::Callbacks::StoreImageDataForLaterValidation(ULONG64 a1)
{
  struct_v2 *pEntryPoint; // rax
  struct_v2 *v2; // rbx
  int v4; // [rsp+58h] [rbp+10h] BYREF
  __int64 v5; // [rsp+60h] [rbp+18h] BYREF
  struct_v2 *v6; // [rsp+68h] [rbp+20h] BYREF

  pEntryPoint = EAC::Memory::GetUsermodeProcessEntryPoint(a1);
  v2 = pEntryPoint;
  if ( pEntryPoint )
  {
    v6 = pEntryPoint;
    v5 = 23i64;
    LODWORD(pEntryPoint) = EAC::Imports::NtProtectVirtualMemory(-1i64, &v6, &v5, 0x40u, &v4);
    if ( pEntryPoint >= 0 )
    {
      EAC::Callbacks::IsInUsermodeAddressSpace(v2, 23i64, 1);
      v2->oword0 = xmmword_140060E58;
      v2->dword10 = 0;
      v2->word14 = 0xD0FF;
      v2->byte16 = 0xC3;
      *(&v2->oword0 + 1) = EAC::Globals::StoredBaseAddressOfMappedModule;
      *(&v2->oword0 + 6) = EAC::Globals_BaseAddress;
      *(&v2->oword0 + 11) = EAC::Globals_BaseAddressOfMappedModule;
      v2->dword10 = EAC::Globals::EntryPointOfMappedModule;
      byte_140073BE7 = 1;
      LOBYTE(pEntryPoint) = EAC::Imports::NtProtectVirtualMemoryWrapper(v2, 23i64, v4, &v4);
    }
  }
  return pEntryPoint;
}

void __fastcall EAC::Callbacks::MapAnotherImage(_QWORD *a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  if ( a1 )
  {
    if ( EAC::Imports::PsGetCurrentProcess() == a1[1] )
    {
      v2 = EAC::Imports::PsGetCurrentProcess();
      v3 = sub_14000D244(v2);
      if ( v3 )
      {
        if ( !*(v3 + 2) )
        {
          *&v13 = 0x173C5BB8ECB50821i64;
          *(&v13 + 1) = 0xE19624F85FCC66AFui64;
          v14 = -434358038;
          v15 = 1143605379;
          v16 = -20;
          v4 = EAC::Memory::DecryptStr22(&v13, v17);
          v5 = EAC::Callbacks::GetUsermodeModuleWrapper(v4);
          memset(v17, 0, 0x1Aui64);
          if ( v5 )
          {
            v17[0] = -144606394;
            v17[1] = 1841444895;
            v17[2] = 1227386293;
            LOBYTE(v17[3]) = 96;
            v6 = EAC::Memory::DecryptStr13(v17, &v13);
            v7 = v6;
            v8 = a1[23];
            v9 = a1[22];
            if ( v9 && v8 && v6 )
            {
              if ( EAC::Memory::GetProcessArchitectureTypeWrapper(a1[23]) == 64 )
                EAC::Callbacks::MapAnotherImage64Bit(v9, v8, v7);
              else
                EAC::Callbacks::MapAnotherImage32Bit(v9, v8, v7);
            }
            memset(&v13, 0, 0xDui64);
            EAC::Callbacks::IsInUsermodeAddressSpace(a1[44], 60i64, 1);
            v10 = a1[44];
            v18 = *v10;
            v19 = *(v10 + 16);
            v13 = *(v10 + 32);
            v20 = *(v10 + 48);
            v11 = *(v10 + 56);
            *&v19 = 0i64;
            DWORD2(v19) = 0;
            EAC::Callbacks::IsInUsermodeAddressSpace(a1[23], 4096i64, 1);
            EAC::Callbacks::RandomizeRegion(a1[23], 4096i64);
            v12 = a1[44];
            *v12 = 0i64;
            *(v12 + 16) = v19;
            *(v12 + 32) = v13;
            *(v12 + 48) = v20;
            *(v12 + 56) = v11;
          }
        }
      }
    }
  }
}

