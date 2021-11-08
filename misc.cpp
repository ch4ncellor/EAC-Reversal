bool EAC::Callbacks::EnableTSX()
{
  unsigned __int64 v0; // r9
  unsigned __int64 newtsx; // rax

  v0 = __readmsr(0x122u);
  _disable();
  __writemsr(0x122u, v0 & 0xFFFFFFFFFFFFFFFEui64);//  MSR_IA32_TSX_CTRL
  newtsx = __readmsr(0x122u);
  __writemsr(0x122u, v0);                       //  MSR_IA32_TSX_CTRL
  _enable();
  return (newtsx & 1) == 0;
}

char __fastcall EAC::Memory::VMRead_Wrapper(__int64 _RCX, __int64 _RDX)
{
  char v2; // cf
  char v3; // zf

  __asm { vmread  qword ptr [rdx], rcx }
  return v2 + v2 + v3;
}

char EAC::Callbacks::DetectHyperVisor()
{
  char v1; // [rsp+50h] [rbp+8h] BYREF

  EAC::Memory::VMRead_Wrapper(0i64, &v1);
  return 1;
}

unsigned __int64 EAC::Callbacks::GetstHyperIface()
{
  return __readmsr(0x40000001u);                // Hypervisor interface
}

bool EAC::Callbacks::DSEFixDetection()
{
  int nFlags; // ebx
  _DWORD *pooltagInformation; // rax
  void *v2; // rdx
  unsigned int v3; // er9
  unsigned int v4; // er8
  _DWORD *entry; // rcx
  int v6; // eax

  nFlags = 0;
  pooltagInformation = EAC::Callbacks::QuerySystemInformation(0x16u, 0x10000u, 0x100000u, 0i64);
  v2 = pooltagInformation;
  if ( pooltagInformation )
  {
    v3 = *pooltagInformation;
    v4 = 0;
    if ( *pooltagInformation )
    {
      entry = pooltagInformation + 3;
      do
      {
        if ( nFlags == 3 )
          break;
        v6 = *(entry - 1);
        if ( v6 == 'rcIC' )
        {
          if ( *entry > entry[1] )
            nFlags |= 1u;
        }
        else if ( v6 == 'csIC' && *entry > entry[1] )// called by CiValidateImageHeader
        {
          nFlags |= 2u;
        }
        ++v4;
        entry += 10;
      }
      while ( v4 < v3 );
    }
    EAC::Memory::ExFreePool(v2);
  }
  else
  {
    nFlags = 3;
  }
  return nFlags == 3;
}

char __fastcall EAC::Callbacks::WriteGameCrashInfoToRegistry(PVOID ValueData)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  LOBYTE(v2) = 0;
  HIDWORD(v30) = 0;
  v19 = 0i64;
  v20 = 0i64;
  v21 = 0i64;
  v22 = 0i64;
  v23 = 0i64;
  v24 = 0i64;
  v25 = 0i64;
  if ( ValueData )
  {
    v2 = EAC::Imports::PsGetCurrentProcess();
    if ( v2 == *(ValueData + 1) )
    {
      v3 = EAC::Imports::PsGetCurrentProcess();
      v4 = EAC::Memory::ResolveImportWrapper(qword_140074158, &qword_140074158, 0i64);
      LODWORD(v2) = v4 ? v4(v3) : 0xC0000002;
      v28 = v2;
      if ( v2 || *(ValueData + 137) )
      {
        v30 = MEMORY[0xFFFFF78000000014];
        v5 = IoGetCurrentProcess();
        v26[0] = PsGetProcessCreateTimeQuadPart(v5);
        v29 = EAC::Memory::GetCurrentTime(*(ValueData + 6));
        v27 = *(ValueData + 4);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameState",
          4u,
          ValueData + 548,
          4u);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameCrashGameID",
          4u,
          ValueData,
          4u);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameCrashPID",
          4u,
          &v27,
          4u);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameCrashCreateTime",
          0xBu,
          v26,
          8u);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameCrashExitTime",
          0xBu,
          &v30,
          8u);
        RtlWriteRegistryValue(
          0,
          L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
          L"ErrRpt_GameCrashExitStatus",
          4u,
          &v28,
          4u);
        LOBYTE(v2) = RtlWriteRegistryValue(
                       0,
                       L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                       L"ErrRpt_GameCrashInfo01",
                       4u,
                       &v29,
                       4u);
        v6 = *(ValueData + 23);
        v7 = v6 + *(ValueData + 24);
        v8 = *(ValueData + 44);
        if ( v8 )
        {
          LOBYTE(v2) = EAC::Callbacks::IsInUsermodeAddressSpace(v8, 60i64, 1);
          v9 = *(ValueData + 44);
          v10 = 0i64;
          v18 = 0i64;
          if ( v9 )
          {
            for ( i = 0i64; ; ++i )
            {
              v26[1] = i;
              if ( i >= 8 )
                break;
              LOBYTE(v2) = *(v9 + 4 * i + 28) ^ 0x90;
              *(&v18 + i) = v2;
              v10 = v18;
            }
          }
          if ( v10 )
          {
            LOBYTE(v2) = EAC::Callbacks::IsInUsermodeAddressSpace(v10, 40i64, 1);
            v12 = *(v10 + 24);
            v13 = *(v10 + 32);
            if ( v12 )
            {
              LOBYTE(v2) = EAC::Callbacks::IsInUsermodeAddressSpace(*(v10 + 24), 64i64, 1);
              if ( *v12 )
              {
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo02",
                  4u,
                  (v12 + 12),
                  4u);
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo03",
                  0xBu,
                  (v12 + 16),
                  8u);
                v14 = *(v12 + 16);
                if ( v14 <= v6 || v14 > v7 )
                  v15 = 0i64;
                else
                  v15 = v14 - v6;
                v19 = v15;
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo04",
                  0xBu,
                  &v19,
                  8u);
                if ( *(v12 + 28) )
                  v20 = *(v12 + 32);
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo05",
                  0xBu,
                  &v20,
                  8u);
                if ( *(v12 + 28) >= 2u )
                  v21 = *(v12 + 40);
                LOBYTE(v2) = RtlWriteRegistryValue(
                               0,
                               L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                               L"ErrRpt_GameCrashInfo06",
                               0xBu,
                               &v21,
                               8u);
              }
            }
            if ( v13 )
            {
              LOBYTE(v2) = EAC::Callbacks::IsInUsermodeAddressSpace(v13, 52i64, 1);
              if ( *v13 )
              {
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo07",
                  4u,
                  (v13 + 12),
                  4u);
                v16 = *(v13 + 16);
                if ( v16 )
                {
                  v22 = *(v13 + 20);
                  v16 = *(v13 + 16);
                }
                if ( v16 >= 2 )
                {
                  v23 = *(v13 + 28);
                  v16 = *(v13 + 16);
                }
                if ( v16 >= 3 )
                {
                  v24 = *(v13 + 36);
                  v16 = *(v13 + 16);
                }
                if ( v16 >= 4 )
                  v25 = *(v13 + 44);
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo08",
                  0xBu,
                  &v22,
                  8u);
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo09",
                  0xBu,
                  &v23,
                  8u);
                RtlWriteRegistryValue(
                  0,
                  L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                  L"ErrRpt_GameCrashInfo10",
                  0xBu,
                  &v24,
                  8u);
                LOBYTE(v2) = RtlWriteRegistryValue(
                               0,
                               L"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat",
                               L"ErrRpt_GameCrashInfo11",
                               0xBu,
                               &v25,
                               8u);
              }
            }
          }
        }
      }
    }
  }
  return v2;
}

__int64 __fastcall EAC::Callbacks::TimingCheck()
{
  __int64 v0; // r12
  __int64 v1; // r13
  __int64 v2; // r14
  __int64 v3; // r15
  __int64 v4; // r10
  __int64 v5; // r11
  __int64 v6; // r9
  __int64 v7; // rdi
  unsigned __int64 v8; // r8
  unsigned __int64 v14; // rax
  __int64 v15; // rbx
  unsigned __int64 v16; // rcx
  unsigned __int64 v17; // rax
  unsigned __int64 v18; // kr00_8
  _QWORD v20[17]; // [rsp-A8h] [rbp-F8h] BYREF
  _QWORD v21[8]; // [rsp-20h] [rbp-70h] BYREF
  __int128 v22; // [rsp+20h] [rbp-30h]
  __int128 v23; // [rsp+30h] [rbp-20h]
  __int64 v24; // [rsp+40h] [rbp-10h]
  __int64 vars0; // [rsp+50h] [rbp+0h] BYREF

  v22 = 0i64;
  v24 = 0i64;
  v23 = 0i64;
  v4 = KeGetCurrentIrql();
  __writecr8(0xFui64);
  v5 = *(&v23 + 1);
  v6 = v24 + 100;
  v7 = v6;
  do
  {
    v8 = __rdtsc();
    _RAX = 1i64;
    __asm { cpuid }
    *&v22 = __PAIR64__(_RBX, _RAX);
    *(&v22 + 1) = __PAIR64__(_RDX, _RCX);
    v14 = __rdtsc();
    v5 += ((HIDWORD(v14) << 32) | v14) - v8;
    --v7;
  }
  while ( v7 );
  v15 = v24;
  *(&v23 + 1) = v5;
  do
  {
    v16 = __rdtsc();
    v17 = __rdtsc();
    v15 += ((HIDWORD(v17) << 32) | v17) - v16;
    --v6;
  }
  while ( v6 );
  v24 = v15;
  __writecr8(v4);
  v21[3] = -1074443376i64;
  v21[2] = -2003135156i64;
  v18 = __readeflags();
  v21[1] = v18;
  v21[0] = 15i64;
  v20[16] = v21;
  v20[15] = HIDWORD(v17) << 32;
  v20[14] = v5;
  v20[13] = v4;
  v20[12] = 0i64;
  v20[11] = v1;
  v20[10] = qword_140052A70;
  v20[9] = v4;
  v20[8] = v15;
  v20[7] = &vars0;
  v20[6] = v0;
  v20[5] = 0i64;
  v20[4] = v8;
  v20[3] = v2;
  v20[2] = v3;
  v20[1] = 0i64;
  v20[0] = 0i64;
  return sub_1418A2D0C(v20);
}

void __fastcall EAC::Callbacks::HandleUsermodeOperation(__int64 a1, __int64 a2, _DWORD *a3)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  pProcess = 0i64;
  nCallbackType = 0i64;
  v5 = *(a2 + 32);
  if ( !v5 )
    goto LABEL_49;
  v6 = *(a2 + 16);
  if ( v6 <= 8 )
    goto LABEL_49;
  if ( *(a1 + 112) != v5 )
    goto LABEL_49;
  if ( *(a2 + 8) != v6 )
    goto LABEL_49;
  EAC::Callbacks::IsInUsermodeAddressSpace(v5, v6, 1);
  v7 = EAC::Memory::ExAllocatePoolWithRandomTag2(v6);
  nCallbackType = v7;
  if ( !v7 )
    goto LABEL_49;
  EAC::Memory::memmove(v7, v5, v6);
  pProcess = EAC::Memory::GetPEPROCESS(*(nCallbackType + 4));
  if ( !pProcess )
    goto LABEL_49;
  EAC::Imports::PsGetCurrentProcess();
  if ( !sub_140012D18() )
    goto LABEL_49;
  if ( *nCallbackType == 1 )
  {
    if ( v6 != 40 )
      goto LABEL_49;
    v12 = EAC::Memory::AllocateMemoryInProcess(pProcess[1], nCallbackType);
  }
  else if ( *nCallbackType == 2 )
  {
    if ( v6 != 40 )
      goto LABEL_49;
    v12 = sub_140045628(pProcess[1], nCallbackType);
  }
  else if ( *nCallbackType == 3 )
  {
    if ( v6 != 40 )
      goto LABEL_49;
    v12 = sub_14004573C(pProcess[1], nCallbackType);
  }
  else if ( *nCallbackType == 4 )
  {
    if ( v6 != 32 )
      goto LABEL_49;
    v12 = EAC::Memory::ProtectMemoryInProcess(pProcess[1], nCallbackType);
  }
  else if ( *nCallbackType == 5 )
  {
    if ( v6 != 28 )
      goto LABEL_49;
    v12 = EAC::Memory::FreeMemoryInProcess(pProcess[1], nCallbackType);
  }
  else
  {
    if ( *nCallbackType != 6 )
    {
      if ( *nCallbackType == 7 )
      {
        if ( v6 != 36 )
          goto LABEL_49;
        v8 = pProcess[1];
        v9 = 0;
        v15 = 0i64;
        if ( !v8 )
          goto LABEL_25;
        if ( !*(nCallbackType + 8) || !*(nCallbackType + 20) || !*(nCallbackType + 28) )
          goto LABEL_49;
        if ( !EAC::Callbacks::KeStackAttachProcess(v8, v13) )
          goto LABEL_25;
        if ( EAC::Imports::ZwQueryVirtualMemory(
               -1i64,
               *(nCallbackType + 8),
               *(nCallbackType + 16),
               *(nCallbackType + 20),
               *(nCallbackType + 28),
               &v15) >= 0 )
        {
          *(nCallbackType + 32) = v15;
          v9 = 1;
        }
      }
      else
      {
        if ( *nCallbackType != 8 || v6 != 36 )
          goto LABEL_49;
        v8 = pProcess[1];
        v9 = 0;
        if ( !v8 )
          goto LABEL_25;
        if ( !*(nCallbackType + 12) || !*(nCallbackType + 20) || !*(nCallbackType + 24) || *(nCallbackType + 32) )
          goto LABEL_49;
        if ( !EAC::Callbacks::KeStackAttachProcess(v8, v13) )
          goto LABEL_25;
        v9 = EAC::Imports::NtSetInformationVirtualMemory(
               v10,
               *(nCallbackType + 8),
               *(nCallbackType + 20),
               *(nCallbackType + 12),
               *(nCallbackType + 24),
               *(nCallbackType + 32)) >= 0;
      }
      EAC::Callbacks::KeUnstackDetachProcess(v8, v13);
LABEL_25:
      v11 = !v9;
      goto LABEL_47;
    }
    if ( v6 != 36 )
      goto LABEL_49;
    v12 = EAC::Memory::ZwFlushVirtualMemoryWrapper(pProcess[1], nCallbackType);
  }
  v11 = v12 == 0;
LABEL_47:
  if ( !v11 )
  {
    EAC::Memory::memmove(v5, nCallbackType, v6);
    *a3 = v6;
  }
LABEL_49:
  if ( nCallbackType )
    EAC::Memory::ExFreePool(nCallbackType);
  if ( pProcess )
    EAC::Memory::ReleasePEPROCESS(pProcess);
}

bool __fastcall EAC::Callbacks::CheckForPhysicalHandle(__int64 a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  if ( !a1 )
    return 0;
  v2 = qword_140073320 == 0;
  *a1 = 0i64;
  *(a1 + 16) = 0i64;
  if ( v2 || _InterlockedCompareExchange(&dword_140074238, 1, 0) )
    return 0;
  v3 = EAC::Callbacks::QuerySystemInformation(0x10u, 0x80000u, 0x1000000u, 0i64);
  if ( !v3 )
    goto LABEL_41;
  v21[0] = 1916479917;
  v22 = 7074;
  v4 = 44i64;
  v21[1] = -1077771171;
  *&physMemDecrypted[2] = 0i64;
  DWORD2(physMemDecrypted[2]) = 0;
  v5 = 1920936433;
  WORD6(physMemDecrypted[2]) = 0;
  v6 = 0i64;
  v21[2] = -456920151;
  v21[3] = 1354280435;
  v21[4] = -1213991906;
  v21[5] = -252238082;
  v21[6] = -16337681;
  v21[7] = 1002680223;
  v21[8] = 38635846;
  v21[9] = -1183450918;
  v21[10] = -1816555846;
  physMemDecrypted[0] = 0i64;
  physMemDecrypted[1] = 0i64;
  v29 = v21;
  v30 = physMemDecrypted;
  do
  {
    *(v30 + v6 * 4) = v29[v6] ^ v5;
    ++v6;
    v5 = __ROR4__(((v5 ^ (v5 << 13)) >> 17) ^ v5 ^ (v5 << 13) ^ (32 * (((v5 ^ (v5 << 13)) >> 17) ^ v5 ^ (v5 << 13))), 1);
  }
  while ( v6 < 11 );
  v29 = v21;
  v30 = physMemDecrypted;
  do
  {
    v7 = v5;
    v5 >>= 8;
    *(v30 + v4) = *(v29 + v4) ^ v7;
    ++v4;
  }
  while ( v4 < 0x2E );
  EAC::Memory::InitializeUnicodeStringWithCString(szPhysMem, physMemDecrypted);// \Device\PhysicalMemory
  ObjectAttributes.Length = 48;
  ObjectAttributes.ObjectName = szPhysMem;
  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.Attributes = 576;
  *&ObjectAttributes.SecurityDescriptor = 0i64;
  if ( ZwOpenSection(&SectionHandle, 1u, &ObjectAttributes) >= 0 )
  {
    v8 = EAC::Imports::ObReferenceObjectByHandle(SectionHandle, 1u, 0i64, 0, &EAC::Globals::Object, 0i64);
    v9 = EAC::Globals::Object;
    if ( v8 < 0 )
      v9 = 0i64;
    EAC::Globals::Object = v9;
    ZwClose(SectionHandle);
  }
  v10 = 0i64;
  memset(physMemDecrypted, 0, 0x2Eui64);
  if ( !*v3 )
    goto LABEL_37;
  sectionObjectType = EAC::Globals::Object;
  v12 = (v3 + 2);
  v13 = 0;
  while ( 1 )
  {
    if ( v12[1] != sectionObjectType || !sectionObjectType || *v12 == 4 )
      goto LABEL_21;
    v14 = *(v12 + 3);
    v15 = EAC::Memory::ResolveImportWrapper(qword_140073D58, &qword_140073D58, 0i64);
    if ( !v15 || !v15(v14) )
      break;
    sectionObjectType = EAC::Globals::Object;
LABEL_21:
    ++v10;
    v12 += 3;
    if ( v10 >= *v3 )
      goto LABEL_38;
  }
  v16 = EAC::Memory::GetProcessImageFilename(*v12, v24);
  if ( v16 )
    v13 = sub_140021608(v24, v26);
  v17 = -v13;
  v18 = (v26 & -(v17 != 0));
  if ( !*(a1 + 4) )
  {
    *a1 = 1;
    *(a1 + 4) = 13;
    if ( v18 )
    {
      if ( *((v26 & -(v17 != 0)) + 8) && *v18 && *((v26 & -(v17 != 0)) + 2) && !*(a1 + 8) )
      {
        if ( a1 == 0xFFFFFFFFFFFFFFF0ui64 )
          v19 = 0;
        else
          v19 = EAC::Memory::AllocateCopyUnicodeString(a1 + 0x10, v18, *v18);
        *(a1 + 8) = v19;
      }
    }
  }
  if ( v16 )
    EAC::Memory::FreeUnicdeString(v24);
LABEL_37:
  sectionObjectType = EAC::Globals::Object;
LABEL_38:
  if ( sectionObjectType )
  {
    ObfDereferenceObject(sectionObjectType);
    EAC::Globals::Object = 0i64;
  }
  EAC::Memory::ExFreePool(v3);
LABEL_41:
  _InterlockedExchange(&dword_140074238, 0);
  return *(a1 + 4) != 0;
}
