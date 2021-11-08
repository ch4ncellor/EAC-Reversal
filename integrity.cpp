char EAC::Callbacks::CheckIfExportsAreHooked()
{
  char v0; // bl
  __int64 pExport1; // rbp
  __int64 pExport2; // rdi
  __int64 pExport3; // rsi
  __int64 v4; // r14
  __int64 v5; // r15
  __int64 v6; // rax

  v0 = 0;
  pExport1 = EAC::Memory::FindExport(&unk_14006C808);
  pExport2 = EAC::Memory::FindExport(&unk_14006C820);
  pExport3 = EAC::Memory::FindExport(&unk_14006C838);
  v4 = sub_140027C5C(1i64);
  v5 = sub_140027C5C(2i64);
  v6 = sub_140027C5C(0i64);
  if ( pExport1 && pExport2 && pExport3 && pExport3 == v5 && pExport1 == v4 && pExport2 == v6 )
    return 1;
  EAC::Callbacks::ReportViolation(0xE7F46F3i64, 0i64, 0i64);
  return v0;
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
