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