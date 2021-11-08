void __fastcall EAC::Callbacks::ScanGameProcess(ULONG64 *a1, char a2, __int64 a3, int a4, int a5, int a6, int a7)
{
  int v7; // er8
  ULONG64 v8; // rdx

  if ( (a2 & 1) != 0 )
  {
    EAC::Callbacks::CheckForManualMappedModule(a1);
  }
  else
  {
    if ( (a2 & 4) != 0 )
    {
      v7 = *(*a1 + 26) >> 14;
      LOBYTE(v7) = (*(*a1 + 26) & 0x4000) != 0;
      LODWORD(v8) = 0;
    }
    else
    {
      v8 = a1[1];
      v7 = 0;
    }
    (sub_14001A790)(a1, v8, v7, a4, a5, a6, a7);
  }
}

void __fastcall EAC::Callbacks::ProtectGameProcess(unsigned int *a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v2 = 0;
  v68 = 0;
  v3 = 0i64;
  v4 = 0i64;
  v58[0] = 0;
  KeQueryTimeIncrement();
  if ( !a1 || *a1 == 197 )
    return;
  v5 = EAC::Memory::ExAllocatePoolWithRandomTag2(0x4000i64);
  v62 = v5;
  if ( !v5 )
    goto LABEL_85;
  v3 = EAC::Memory::ExAllocatePoolWithRandomTag2(1024i64);
  v63 = v3;
  if ( !v3 )
    goto LABEL_85;
  v6 = EAC::Memory::ExAllocatePoolWithRandomTag2(0x8000i64);
  v4 = v6;
  v64 = v6;
  if ( !v6 )
    goto LABEL_85;
  v59 = v6 + 2;
  v61 = v6 + 0x8000;
  if ( !EAC::Callbacks::KeStackAttachProcess(*(a1 + 1), v67) )
    goto LABEL_83;
  for ( i = 0i64; !*(a1 + 544) && EAC::Imports::NtQueryVirtualMemory(-1i64, i, 0i64, &i, 48i64); i += v54 )
  {
    v7 = (v54 + 4095) & 0xFFFFFFFFFFFFF000ui64;
    if ( !v7 )
      v7 = 4096i64;
    v54 = v7;
    v8 = v53;
    if ( v53 != i )
      goto LABEL_19;
    if ( v57 == 0x1000000 )
    {
      if ( !v53 || !EAC::Memory::PebImageByBaseWin64(v53) && !EAC::Memory::PebImageByBaseWow64(v8) )
      {
        v9 = EAC::Imports::GetProcessBaseAddress(*(a1 + 1));
        if ( v53 != v9 )
        {
          sub_140031F70(a1, &i);
          goto LABEL_35;
        }
      }
LABEL_19:
      if ( v57 == 0x1000000 && (v56 & 0x100) != 0 )
      {
        EAC::Callbacks::DetectLoadedModulesInGame(a1, 0x342B6272u, v53, 0i64);
        v34 = -1969993559;
        v35 = -1144243536;
        v36 = 242064136;
        v37 = 187676638;
        v38 = -1991878171;
        v39 = 96452294;
        v40 = -149557856;
        v41 = -694104463;
        v42 = -1557300779;
        v43 = -566847724;
        v44 = 510674766;
        v45 = 839459207;
        v46 = -379320832;
        v47 = 1465384362;
        v48 = 969356546;
        v49 = 1556836777;
        v50 = 307426473;
        v10 = v2 | 1;
        v12 = 0;
        if ( EAC::Memory::DecryptStr16(&v34, v66) )
        {
          v11 = *(a1 + 67);
          if ( v11 )
          {
            if ( !*(v11 + 32) )
              v12 = 1;
          }
        }
        v68 = v10 & 0xFFFFFFFE;
        memset(v66, 0, 0x44ui64);
        if ( v12 )
        {
          v34 = -1969993559;
          v35 = -1144243536;
          v36 = 242064136;
          v37 = 187676638;
          v38 = -1991878171;
          v39 = 96452294;
          v40 = -149557856;
          v41 = -694104463;
          v42 = -1557300779;
          v43 = -566847724;
          v44 = 510674766;
          v45 = 839459207;
          v46 = -379320832;
          v47 = 1465384362;
          v48 = 969356546;
          v49 = 1556836777;
          v50 = 307426473;
          v13 = EAC::Memory::DecryptStr16(&v34, v66);
          LODWORD(v33) = v55;
          LODWORD(v32) = v57;
          sub_14002B218(*(a1 + 67), v13, v54, v56, v32, v33);
          memset(v66, 0, 0x44ui64);
        }
        goto LABEL_35;
      }
    }
    if ( EAC::Imports::MmGetPhysicalForVirtual(i) )
    {
      v14 = *(a1 + 23);
      if ( v14 >= i && v14 < v54 + i )
        continue;
    }
    else if ( v54 <= 0x1000 || !EAC::Imports::MmGetPhysicalForVirtual(i - 4096 + v54) )
    {
      continue;
    }
LABEL_35:
    v15 = v54;
    v60 = v54;
    v65 = v54;
    v16 = v54;
    if ( v54 > 0x100000 )
      v16 = 0x100000i64;
    v54 = v16;
    EAC::Callbacks::IsInUsermodeAddressSpace(i, v16, 1);
    v17 = sub_14000F73C(&i, v5, 1024);
    v20 = v17;
    v69 = v17;
    if ( v17 )
    {
      nHASH = EAC::Memory::GetSomeHash(v18, 2, v5, v17);
      v22 = nHASH;
      if ( (nHASH != 0x1523ABE1 || v57 == 0x20000)// whitelisted module hashes? lol
        && (nHASH != 0x3EF9544D || v56 == 64)
        && (nHASH != 0x7D73439 || v57 == 0x20000) )
      {
        if ( nHASH == 0x1D73F827 )
        {
          if ( v57 == 0x1000000
            || (v23 = *a1, v23 <= 0x3E) && (v24 = 0x4002000800121000i64, _bittest64(&v24, v23))
            || v23 == 81
            || v23 == 89 )
          {
            v22 = 0;
          }
        }
        if ( v22 )
          goto SKIP_LOOP_LABEL;
      }
      v22 = 0;
      for ( j = 0; ; ++j )
      {
        v58[2] = j;
        if ( j >= v20 )
          break;
        v26 = 0;
        v27 = 0;
        v51 = 0i64;
        v28 = 0;
        for ( k = 0i64; ; k = (k + 1) )
        {
          v58[1] = k;
          LODWORD(v51) = v5[4 * j + 2];
          v29 = k == v51;
          if ( k >= v51 )
            break;
          v30 = *(k + *&v5[4 * j]);
          if ( v30 == 120 )
          {
            v26 |= 1u;
            v28 = 0;
            v51 = ++v27;
            if ( v27 == 3 )
              v26 |= 4u;
          }
          else
          {
            if ( v30 != 63 )
            {
              v29 = k == v51;
              break;
            }
            v26 |= 2u;
            v27 = 0;
            LODWORD(v51) = 0;
            HIDWORD(v51) = ++v28;
            if ( v28 == 2 )
              v26 |= 8u;
          }
        }
        if ( v29 && v26 == 15 )
        {
          v22 = 693986245;
          v20 = v69;
          break;
        }
        v20 = v69;
      }
      if ( v22 )
SKIP_LOOP_LABEL:
        sub_140031DC8(v22, &i, v5, v20, a1);
      v15 = v60;
    }
    if ( v54 > 0x1000 )
      v59 = EAC::Callbacks::SomeDisassemblerShitWrapper(&i, v3, k, v59, v61, v58);
    v2 = v68;
    v54 = v15;
  }
  EAC::Callbacks::KeUnstackDetachProcess(*(a1 + 1), v67);
  v31 = a1[10];
  if ( (v31 == 64 && i < 0x7FFFFFF0000i64 || v31 == 32 && i < 0x7FFE0000)
    && EAC::Imports::PsGetProcessExitProcessCalled(*(a1 + 1))
    && !*(a1 + 544) )
  {
    EAC::Callbacks::ReportViolation_1(a1, 0x49C7C002i64, &i, 8i64, 0i64);
  }
LABEL_83:
  if ( v58[0] )
  {
    *v4 = v58[0];
    EAC::Callbacks::ReportViolation_1(a1, 0x7A8B5AF5i64, v4, (v59 - v4), 0i64);
  }
LABEL_85:
  if ( v4 )
    EAC::Memory::ExFreePool(v4);
  if ( v3 )
    EAC::Memory::ExFreePool(v3);
  if ( v5 )
    EAC::Memory::ExFreePool(v5);
}

void __fastcall EAC::Callbacks::DetectLoadedModulesInGame(__int64 a1, unsigned int a2, unsigned __int64 a3, __int64 a4)
{
  unsigned __int16 *v4; // rsi
  __int64 v7; // rax
  __int16 v8; // bx
  __int64 v9; // rax
  int v10; // eax
  unsigned int v11; // er12
  _OWORD *v12; // rax
  __int64 v13; // r14
  char *i; // rax
  __int64 v15; // rdx
  unsigned int v16; // ebx
  __int64 v17[2]; // [rsp+50h] [rbp-88h] BYREF
  char v18[16]; // [rsp+60h] [rbp-78h] BYREF
  char *v19; // [rsp+70h] [rbp-68h] BYREF
  char *v20; // [rsp+78h] [rbp-60h]
  unsigned __int64 v21; // [rsp+88h] [rbp-50h]
  int v22; // [rsp+98h] [rbp-40h]

  if ( a1 )
  {
    v4 = a4;
    if ( a3 )
    {
      if ( !a4 || !*(a4 + 8) || !*a4 || !*(a4 + 2) )
        v4 = (v18 & -(EAC::Memory::GetMappedFilename(-1i64, a3, v18) != 0));
      v7 = EAC::Imports::PsGetCurrentProcess();
      v8 = EAC::Imports::PsGetCurrentProcessID(v7);
      v9 = EAC::Imports::PsGetCurrentProcess();
      v10 = EAC::Imports::PsGetProcessWow64(v9);
      v11 = 0x8000;
      v12 = EAC::Memory::CopyProcessInformation(a3, 0x1000ui64, 0x8000ui64, 0, v10, v4, v8, v17);
      v13 = v12;
      v17[1] = v12;
      if ( v12 )
      {
        *(v12 + 22) = 0;
        for ( i = a3; ; i = &v19[v21] )
        {
          v19 = i;
          if ( !v11 )
            break;
          if ( !EAC::Imports::NtQueryVirtualMemory(-1i64, i, 0i64, &v19, 48i64) )
            break;
          if ( v20 != a3 )
            break;
          v15 = (v21 + 4095) & 0xFFFFFFFFFFFFF000ui64;
          v21 = v15;
          if ( !v15 )
            break;
          EAC::Callbacks::IsInUsermodeAddressSpace(v19, v15, 1);
          if ( v22 == 0x1000000 && v19 == v20 )
          {
            *(v13 + 26) |= 2u;
            if ( !EAC::Memory::GetImageBase(v19, v21) )
              *(v13 + 26) |= 0x80u;
          }
          v16 = v11;
          if ( v11 > v21 )
            v16 = v21;
          EAC::Memory::memmove((v17[0] + *(v13 + 22)), v19, v16);
          *(v13 + 22) += v16;
          v11 -= v16;
        }
        EAC::Callbacks::ReportViolation_1(a1, a2, v13, (*(v13 + 10) + *(v13 + 22)), 0i64);
        EAC::Memory::ExFreePool(v13);
      }
      if ( v4 == v18 )
        EAC::Memory::FreeUnicdeString(v18);
    }
  }
}

void __fastcall EAC::Callbacks::DetectLoadedModulesInGame2(__int64 pStr, __int64 a2, unsigned int a3)
{
  __int64 v4; // r14
  unsigned __int64 v6; // r12
  _OWORD *v7; // rax
  __int64 v8; // rbx
  __int64 v9; // rsi
  unsigned int v10; // er13
  __int64 v11; // rdi
  unsigned __int64 v12; // r15
  __int64 v13; // [rsp+80h] [rbp+8h]
  __int64 v14; // [rsp+98h] [rbp+20h] BYREF

  if ( pStr )
  {
    v13 = pStr;
    v4 = a2;
    if ( *(pStr + 32) )
    {
      if ( a2 )
      {
        if ( a3 )
        {
          v6 = 0x8000i64;
          v7 = EAC::Memory::CopyProcessInformation(*(pStr + 16), *(pStr + 24), 0x8000ui64, 4, 64, pStr, 0, &v14);
          v8 = v7;
          if ( v7 )
          {
            if ( *(pStr + 28) )
              *(v7 + 26) |= 0x400u;
            v9 = 0i64;
            v10 = 0;
            if ( a3 )
            {
              v11 = v14;
              do
              {
                v12 = (*(v4 + 8) + 1);
                if ( v12 > v6 )
                  break;
                EAC::Memory::memmove((v9 + v11), *v4, v12);
                v9 += v12;
                v6 -= v12;
                ++v10;
                v4 += 16i64;
              }
              while ( v10 < a3 );
              if ( v9 )
              {
                EAC::Callbacks::ReportViolation(*(v13 + 32), v8, (v9 + *(v8 + 10)));
                memset(v8, 0, (v9 + *(v8 + 10)));
              }
            }
            EAC::Memory::ExFreePool(v8);
          }
        }
      }
    }
  }
}

void EAC::Callbacks::CloseGameProcess()
{
  if ( EAC::Globals::GameProcessID )
  {
    EAC::Callbacks::TerminateUsermodeProcess(EAC::Globals::GameProcessID, 0);
    EAC::Globals::GameProcessID = 0i64;
  }
  if ( Event )
  {
    ObfDereferenceObject(Event);
    Event = 0i64;
  }
  EAC::Globals::ProcessID = 0i64;
}

char __fastcall EAC::Callbacks::ResetGameProcessID(__int64 a1)
{
  char result; // al

  if ( !a1 || a1 != EAC::Globals::GameProcessID )
    return 0;
  EAC::Globals::ProcessID = 0i64;
  result = 1;
  EAC::Globals::GameProcessID = 0i64;
  return result;
}
