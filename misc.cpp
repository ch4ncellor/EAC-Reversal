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
