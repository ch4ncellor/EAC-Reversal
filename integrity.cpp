// Thanks to https://github.com/ch4ncellor/EAC-Reversal/issues/1
char EAC::Callbacks::ValidateExports()
{
  char v0; // bl
  __int64 PsProcessType; // rbp
  __int64 MmGetSystemRoutineAddress; // rdi
  __int64 ZwDeleteKey; // rsi
  __int64 PsProcessTypeHMAP; // r14
  __int64 ZwDeleteKeyHMAP; // r15
  __int64 MmGetSystemRoutineAddressHMAP; // rax

  v0 = 0;
  PsProcessType = EAC::Memory::FindExport(&PsProcessTypeHash);
  MmGetSystemRoutineAddress = EAC::Memory::FindExport(&MmGetSystemRoutineAddressHash);
  ZwDeleteKey = EAC::Memory::FindExport(&ZwDeleteKeyHash);
  PsProcessTypeHMAP = EAC::Memory::LookupImportHMAP(1i64);
  ZwDeleteKeyHMAP = EAC::Memory::LookupImportHMAP(2i64);
  MmGetSystemRoutineAddressHMAP = EAC::Memory::LookupImportHMAP(0i64);
  if ( PsProcessType
    && MmGetSystemRoutineAddress
    && ZwDeleteKey
    && ZwDeleteKey == ZwDeleteKeyHMAP
    && PsProcessType == PsProcessTypeHMAP
    && MmGetSystemRoutineAddress == MmGetSystemRoutineAddressHMAP )
  {
    return 1;
  }
  EAC::Callbacks::ReportViolation(0xE7F46F3i64, 0i64, 0i64);
  return v0;
}

LONG_PTR __fastcall EAC::Callbacks::ValidatePreviouslyMappedImage(char **a1, int a2, void *a3, __int64 a4)
{
  LONG_PTR result; // rax
  char *v8; // r14
  void *v9; // rcx
  unsigned __int64 v10; // r8
  void *v11; // rdx
  unsigned __int64 i; // r8
  bool v13; // [rsp+30h] [rbp-88h]
  PVOID v14; // [rsp+38h] [rbp-80h] BYREF
  PVOID Object[3]; // [rsp+40h] [rbp-78h] BYREF
  _LARGE_INTEGER Timeout; // [rsp+58h] [rbp-60h] BYREF
  _OWORD *v17; // [rsp+60h] [rbp-58h]
  char v18[56]; // [rsp+68h] [rbp-50h] BYREF
  void *retaddr; // [rsp+B8h] [rbp+0h] BYREF
  PVOID v20; // [rsp+D0h] [rbp+18h] BYREF
  __int64 v21; // [rsp+D8h] [rbp+20h]

  result = &retaddr;
  v21 = a4;
  v20 = a3;
  v17 = a4;
  v13 = 0;
  Object[0] = 0i64;
  v14 = 0i64;
  if ( a4 )
  {
    result = EAC::Memory::memset((a4 + 8), 0, 0xA98ui64);
    *a4 = 1;
    *(a4 + 4) = 6;
    if ( a1 && a1[1] && *a1 && *(a1 + 1) && a2 )
    {
      result = MEMORY[0xFFFFF7800000026C];
      if ( MEMORY[0xFFFFF7800000026C] < 6u
        || MEMORY[0xFFFFF7800000026C] == 6 && (result = 0xFFFFF78000000270ui64, !MEMORY[0xFFFFF78000000270]) )
      {
        *(a4 + 4) = 0;
      }
      else
      {
        result = EAC::Globals::GameProcessID;
        if ( EAC::Globals::GameProcessID && byte_140073BE7 )
        {
          result = EAC::Imports::PsLookupProcessByProcessID(EAC::Globals::GameProcessID, &v20);
          if ( result >= 0 )
          {
            v8 = sub_14003E130();
            Object[2] = v8;
            if ( v8 && EAC::Callbacks::KeStackAttachProcess(v20, v18) )
            {
              if ( EAC::Globals::StoredBaseAddressOfMappedModule )
              {
                EAC::Callbacks::IsInUsermodeAddressSpace(EAC::Globals::StoredBaseAddressOfMappedModule, 4i64, 1);
                v9 = *EAC::Globals::StoredBaseAddressOfMappedModule;
                if ( v9 )
                {
                  if ( ObReferenceObjectByHandle(v9, 2u, ExEventObjectType, 1, Object, 0i64) >= 0 )
                  {
                    EAC::Callbacks::IsInUsermodeAddressSpace(v8, 0xCB4i64, 1);
                    if ( ObReferenceObjectByHandle(*(v8 + 1), 0x100000u, ExEventObjectType, 1, &v14, 0i64) >= 0 )
                    {
                      *(v8 + 2) = a2;
                      v10 = 518i64;
                      if ( *a1 < 0x206ui64 )
                        v10 = *a1;
                      EAC::Memory::memmove(v8 + 12, a1[1], v10);
                      *(v8 + 265) = 0;
                      v11 = 0i64;
                      for ( i = 0i64; ; ++i )
                      {
                        Object[1] = v11;
                        if ( i >= 0x208 )
                          break;
                        v8[v11 + 12] += 64 - 96 * v11;
                        v11 = (i + 1);
                      }
                      EAC::Memory::memset((v8 + 532), 0, 0xAA0ui64);
                      *(v8 + 133) = 1;
                      *(v8 + 134) = 7;
                      *v8 = 1;
                      v13 = 1;
                    }
                    else
                    {
                      v14 = 0i64;
                    }
                  }
                  else
                  {
                    Object[0] = 0i64;
                  }
                }
              }
              EAC::Callbacks::KeUnstackDetachProcess(v20, v18);
              *(a4 + 4) = 7;
              if ( v13 )
              {
                KeSetEvent(Object[0], 0, 1u);
                Timeout.QuadPart = -300000000i64;
                v13 = KeWaitForSingleObject(v14, UserRequest, 0, 0, &Timeout) == 0;
              }
              if ( v14 )
                ObfDereferenceObject(v14);
              if ( Object[0] )
                ObfDereferenceObject(Object[0]);
            }
            if ( v13 )
            {
              if ( EAC::Callbacks::KeStackAttachProcess(v20, v18) )
              {
                EAC::Callbacks::IsInUsermodeAddressSpace(v8, 3252i64, 1);
                EAC::Memory::memmove(v17, v8 + 532, 0xAA0ui64);
                EAC::Memory::memset((v8 + 532), 0, 0xAA0ui64);
                EAC::Callbacks::KeUnstackDetachProcess(v20, v18);
              }
            }
            result = ObfDereferenceObject(v20);
          }
        }
        else
        {
          *(a4 + 4) = 6;
        }
      }
    }
    else
    {
      *(a4 + 4) = 4;
    }
  }
  return result;
}

void __fastcall EAC::Callbacks::DetectAPCLevelIRQL(__int64 a1)
{
  __int64 v1; // rdx
  __int64 v3; // rbx
  void *v4; // rbp
  struct _FAST_MUTEX *v5; // rcx
  __int64 v6; // rbx

  if ( !a1 )
    return;
  v1 = *(a1 + 536);
  v3 = v1;
  if ( !v1 )
    goto LABEL_5;
  if ( KeGetCurrentIrql() <= APC_LEVEL )
  {
    *(v1 + 32) = 1;
    v3 = *(a1 + 536);
LABEL_5:
    if ( !v3 )
      return;
  }
  if ( KeGetCurrentIrql() <= APC_LEVEL )
  {
    ExAcquireFastMutex((v3 + 40));
    v4 = *v3;
    v5 = (v3 + 40);
    v6 = *(v3 + 8);
    ExReleaseFastMutex(v5);
    if ( v6 )
    {
      EAC::Callbacks::ReportViolation_1(a1, 0x50FB7A72i64, v4, (2 * v6 + 2), 0i64);
      memset(v4, 0, 2i64 * (v6 + 1));
    }
  }
}
