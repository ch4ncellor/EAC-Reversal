void __fastcall EAC::Callbacks::CheckForManualMappedModule(ULONG64 *pAnomalyHashStruct)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  if ( pAnomalyHashStruct )
  {
    v11 = 0i64;
    v2 = pAnomalyHashStruct[1];
    if ( v2 )
    {
      EAC::Callbacks::IsInUsermodeAddressSpace(pAnomalyHashStruct[1], 4096i64, 1);
      if ( EAC::Memory::GetPEHeader(v2, 0x1000ui64, 0i64, &v12) )
      {
        v3 = v12;
        v4 = &v12->OptionalHeader + v12->FileHeader.SizeOfOptionalHeader;
        for ( i = 0; i < v3->FileHeader.NumberOfSections && *(pAnomalyHashStruct + 10) != 32; ++i )
        {
          EAC::Callbacks::IsInUsermodeAddressSpace(v4, 40i64, 1);
          v6 = *(v4 + 3);
          if ( v6 )
          {
            v7 = *(v4 + 2);
            if ( v7 )
            {
              if ( (*(v4 + 9) & 0x2000000) == 0 )
              {
                v8 = *v4;
                if ( (*v4 != 'ler.' || *(v4 + 2) != 'co') && v8 != 'slt.' )
                {
                  if ( v8 != 'rsr.' || (v9 = 1, v4[4] != 'c') )
                    v9 = 0;
                  BYTE12(v11) = v9;
                  v10 = v9;
                  if ( (*(*pAnomalyHashStruct + 26) & 0x60) != 0 )
                    v10 = 1;
                  BYTE12(v11) = v10;
                  *&v11 = v2 + v6;
                  DWORD2(v11) = v7;
                  EAC::Callbacks::IsInUsermodeAddressSpace(v2 + v6, v7, 1);
                  EAC::Callbacks::SetHashOfAnomaly(&v11, pAnomalyHashStruct);
                }
              }
            }
          }
          v4 += 40;
        }
      }
    }
  }
}

char __fastcall EAC::Callbacks::CheckForBlacklistedModuleNamesWrapper(__int64 a1)
{
  char v2; // si
  __int64 v3; // rax
  PVOID *v4; // rbx
  unsigned int v5; // edi
  __int64 *v6; // r14
  __int64 v7; // rdi

  v2 = 0;
  v3 = EAC::Memory::ExAllocatePoolWithRandomTag2(4096i64);
  v4 = v3;
  if ( v3 )
  {
    v5 = sub_14000D368(v3);
    if ( v5 )
    {
      ObfDereferenceObject(*v4);
      if ( v5 > 1 )
      {
        v6 = (v4 + 1);
        v7 = v5 - 1;
        do
        {
          if ( !v2 && !sub_140006810(a1) )
            v2 = EAC::Callbacks::CheckForBlacklistedModuleNames(*v6);
          ObfDereferenceObject(*v6++);
          --v7;
        }
        while ( v7 );
      }
    }
    EAC::Memory::ExFreePool(v4);
  }
  return v2;
}

char __fastcall EAC::Callbacks::CheckForBlacklistedModuleNames(__int64 a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  bDidFindBlacklistedModule = 0;
  if ( !EAC::Callbacks::KeStackAttachProcess(a1, v64) )
    return bDidFindBlacklistedModule;
  v42[0] = 404169542;
  v43 = 24194;
  v3 = 20i64;
  v42[1] = 1671252913;
  *&v55[16] = 0;
  *&v55[20] = 0;
  v4 = 409084674;
  v42[2] = 1997423613;
  v42[3] = -2365392;
  v5 = 0i64;
  v42[4] = 1080899897;
  *v55 = 0i64;
  do
  {
    *&v55[v5 * 4] = v42[v5] ^ v4;
    ++v5;
    v4 = _byteswap_ulong(((v4 ^ (v4 << 13)) >> 17) ^ v4 ^ (v4 << 13) ^ (32
                                                                      * (((v4 ^ (v4 << 13)) >> 17) ^ v4 ^ (v4 << 13))));
  }
  while ( v5 < 5 );
  do
  {
    v6 = v4;
    v4 >>= 8;
    v55[v3] = *(v42 + v3) ^ v6;
    ++v3;
  }
  while ( v3 < 0x16 );
  v7 = 1;
  if ( EAC::Callbacks::GetUsermodeModuleWrapper(v55) )// Dumper.dll
  {
    v40[0] = 570211008;
    v41 = -31209;
    v40[1] = -1022839618;
    *&v54[16] = 0;
    v8 = 563133063;
    v40[2] = -738526335;
    v40[3] = 1285740581;
    v9 = 0i64;
    *v54 = 0i64;
    do
    {
      *&v54[v9 * 4] = v40[v9] ^ v8;
      ++v9;
      v8 = -2531012 - 214013 * v8;
    }
    while ( v9 < 4 );
    for ( i = 16i64; i < 0x12; ++i )
    {
      v11 = v8;
      v8 >>= 8;
      v54[i] = *(v40 + i) ^ v11;
    }
    v7 = 3;
    if ( EAC::Callbacks::GetUsermodeModuleWrapper(v54) )// Glob.dll
    {
      v48[0] = 316787955;
      *&v59[16] = 0i64;
      v48[1] = 679437834;
      v48[2] = -1174755841;
      v12 = 392827509;
      v48[3] = -496974842;
      v13 = 0i64;
      v48[4] = 692469395;
      v48[5] = -508318795;
      *v59 = 0i64;
      do
      {
        v12 = _byteswap_ulong(((v12 ^ (v12 >> 7)) << 9) ^ v12 ^ (v12 >> 7) ^ ((((v12 ^ (v12 >> 7)) << 9) ^ v12 ^ (v12 >> 7)) >> 13));
        *&v59[v13 * 4] = v48[v13] ^ v12;
        ++v13;
      }
      while ( v13 < 6 );
      v7 = 7;
      if ( EAC::Callbacks::GetUsermodeModuleWrapper(v59) )// mswsock.dll
      {
        v49[0] = 1462885684;
        *&v58[16] = 0i64;
        v49[1] = -402286035;
        v49[2] = -1169349665;
        v14 = 2101152273;
        v49[3] = -538151392;
        v15 = 0i64;
        v49[4] = -274603261;
        v49[5] = 488391802;
        *v58 = 0i64;
        do
        {
          v14 = __ROR4__(
                  ((v14 ^ (v14 << 13)) >> 7) ^ v14 ^ (v14 << 13) ^ ((((v14 ^ (v14 << 13)) >> 7) ^ v14 ^ (v14 << 13)) << 17),
                  4);
          *&v58[v15 * 4] = v49[v15] ^ v14;
          ++v15;
        }
        while ( v15 < 6 );
        v7 = 15;
        if ( EAC::Callbacks::GetUsermodeModuleWrapper(v58) )//  perl512.dll
        {
          v16 = 1;
LABEL_19:
          v7 &= 0xFFFFFFF7;
          memset(v58, 0, sizeof(v58));
          goto LABEL_20;
        }
      }
    }
  }
  v16 = 0;
  if ( (v7 & 8) != 0 )
    goto LABEL_19;
LABEL_20:
  if ( (v7 & 4) != 0 )
  {
    v7 &= 0xFFFFFFFB;
    memset(v59, 0, sizeof(v59));
  }
  if ( (v7 & 2) != 0 )
  {
    v7 &= 0xFFFFFFFD;
    memset(v54, 0, sizeof(v54));
  }
  v17 = v7 & 0xFFFFFFFE;
  memset(v55, 0, sizeof(v55));
  if ( v16 )
    goto LABEL_54;
  v46[0] = -1918767450;
  v47 = 30032;
  v46[1] = 1716648254;
  v18 = v17 | 0x10;
  v46[2] = -2001414969;
  *&v61[32] = 0;
  v19 = -1915949360;
  v46[3] = -682439642;
  v46[4] = 1479981800;
  v20 = 0i64;
  v46[5] = 747063356;
  v46[6] = -796488994;
  v46[7] = 1471440201;
  *v61 = 0i64;
  *&v61[16] = 0i64;
  do
  {
    v21 = v46[v20] ^ v19;
    v19 = __ROR4__(23449 * v19 + 10042149, 2);
    *&v61[v20 * 4] = v21;
    ++v20;
  }
  while ( v20 < 8 );
  for ( j = 32i64; j < 0x22; ++j )
  {
    v23 = v19;
    v19 >>= 8;
    v61[j] = *(v46 + j) ^ v23;
  }
  if ( EAC::Callbacks::GetUsermodeModuleWrapper(v61) )// vmclientcore.dll
    goto LABEL_44;
  *&v57[16] = 0i64;
  *&v57[24] = 0;
  v18 |= 0x20u;
  v51[0] = 1064449107;
  *v57 = 0i64;
  v51[1] = 1638685829;
  v24 = -1269883487;
  v51[2] = 1103840582;
  v25 = 0i64;
  v51[3] = -554947786;
  v51[4] = -679930175;
  v51[5] = -277811938;
  v51[6] = 434714035;
  do
  {
    v24 = ~(((v24 ^ (v24 << 13)) >> 7) ^ v24 ^ (v24 << 13) ^ ((((v24 ^ (v24 << 13)) >> 7) ^ v24 ^ (v24 << 13)) << 17));
    *&v57[v25 * 4] = v51[v25] ^ v24;
    ++v25;
  }
  while ( v25 < 7 );
  if ( EAC::Callbacks::GetUsermodeModuleWrapper(v57) )// vmwarewui.dll
    goto LABEL_44;
  v44[0] = -1427003179;
  v45 = 16042;
  v18 |= 0x40u;
  v44[1] = -1341968668;
  *&v56[16] = 0i64;
  *&v56[24] = 0;
  v26 = -1432835933;
  *&v56[28] = 0;
  v27 = 0i64;
  v44[2] = 421141858;
  v44[3] = 670852926;
  v44[4] = -1407531516;
  v44[5] = 386858880;
  v44[6] = -1587770893;
  *v56 = 0i64;
  do
  {
    *&v56[v27 * 4] = v44[v27] ^ v26;
    ++v27;
    v26 = -4486779 - 60741 * v26;
  }
  while ( v27 < 7 );
  for ( k = 28i64; k < 0x1E; ++k )
  {
    v29 = v26;
    v26 >>= 8;
    v56[k] = *(v44 + k) ^ v29;
  }
  if ( EAC::Callbacks::GetUsermodeModuleWrapper(v56) )// virtualbox.dll
    goto LABEL_44;
  v52[0] = 1246573564;
  v52[1] = -1435646966;
  v62[0] = 0i64;
  v52[2] = -1583470474;
  v18 |= 0x80u;
  v62[1] = 0i64;
  v52[3] = 1413339661;
  v30 = -678343082;
  v52[4] = 266555639;
  v31 = 0i64;
  v52[5] = 963523025;
  v52[6] = -972779894;
  v52[7] = 1931803890;
  do
  {
    v30 = _byteswap_ulong(((v30 ^ (v30 << 13)) >> 7) ^ v30 ^ (v30 << 13) ^ ((((v30 ^ (v30 << 13)) >> 7) ^ v30 ^ (v30 << 13)) << 17));
    *(v62 + v31 * 4) = v52[v31] ^ v30;
    ++v31;
  }
  while ( v31 < 8 );
  if ( EAC::Callbacks::GetUsermodeModuleWrapper(v62) )//  qtcorevbox4.dll
    goto LABEL_44;
  *&v60[16] = 0i64;
  v50[0] = 1622598650;
  *v60 = 0i64;
  v50[1] = -434380297;
  v18 |= 0x100u;
  v50[2] = 450310602;
  v32 = 967813938;
  v50[3] = -1230501162;
  v33 = 0i64;
  v50[4] = 130594042;
  v50[5] = 877756042;
  do
  {
    v32 = _byteswap_ulong(14767 * v32 + 11512626);
    *&v60[v33 * 4] = v50[v33] ^ v32;
    ++v33;
  }
  while ( v33 < 6 );
  v34 = EAC::Callbacks::GetUsermodeModuleWrapper(v60);// vboxvmm.dll
  v35 = 0;
  if ( v34 )
LABEL_44:
    v35 = 1;
  if ( _bittest(&v18, 8u) )
    memset(v60, 0, sizeof(v60));
  if ( (v18 & 0x80u) != 0 )
  {
    LOBYTE(v18) = v18 & 0x7F;
    memset(v62, 0, sizeof(v62));
  }
  if ( (v18 & 0x40) != 0 )
    memset(v56, 0, sizeof(v56));
  if ( (v18 & 0x20) != 0 )
    memset(v57, 0, sizeof(v57));
  memset(v61, 0, sizeof(v61));
  if ( v35 )
  {
LABEL_54:
    bDidFindBlacklistedModule = 1;
  }
  else
  {
    v53[0] = 1037675329;
    v53[1] = -1518926285;
    v63[0] = 0i64;
    v53[2] = 21725712;
    v36 = 476297892;
    v63[1] = 0i64;
    v53[3] = -814997594;
    v37 = 0i64;
    v53[4] = -1828532299;
    v53[5] = -1535047739;
    v53[6] = -1866569114;
    v53[7] = 1065021894;
    do
    {
      v36 = -(((v36 ^ (v36 << 13)) >> 7) ^ v36 ^ (v36 << 13) ^ ((((v36 ^ (v36 << 13)) >> 7) ^ v36 ^ (v36 << 13)) << 17));
      *(v63 + v37 * 4) = v53[v37] ^ v36;
      ++v37;
    }
    while ( v37 < 8 );
    v38 = EAC::Callbacks::GetUsermodeModuleWrapper(v63);//  netredirect.dll
    bDidFindBlacklistedModule = 0;
    memset(v63, 0, sizeof(v63));
    if ( v38 )
      bDidFindBlacklistedModule = 1;
  }
  EAC::Callbacks::KeUnstackDetachProcess(a1, v64);
  return bDidFindBlacklistedModule;
}

char EAC::Callbacks::CheckModuleExtension(unsigned __int64 a1, char a2, unsigned int *a3, __int64 a4, ...)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  va_start(va1, a4);
  va_start(Pa, a4);
  Pa = va_arg(va1, PVOID);
  v47 = va_arg(va1, _WORD *);
  v45 = a4;
  v44 = a2;
  v36 = 0;
  EAC::Memory::memset(&v40, 0, 0x98ui64);
  Pa = 0i64;
  v8 = 0i64;
  v9 = 0i64;
  if ( !a1 || !a3 || !a4 )
    return 0;
  if ( a2 == 32 )
  {
    v11 = a3[32];
    v12 = a3[33];
  }
  else
  {
    if ( a2 != 64 )
      return 0;
    v11 = a3[36];
    v12 = a3[37];
  }
  v13 = a3[20];
  v39 = v13;
  v14 = (a1 + v11);
  v15 = v13 + a1;
  v38 = v13 + a1;
  if ( !v13 || v12 < 0x14ui64 || v14 <= a1 || v14 + v12 > v15 )
    return 0;
  v40.m128_i32[3] = 0xEFCDAB89;
  v41 = -1732584194;
  v42 = 271733878;
  v40.m128_i32[0] = 0;
  *(v40.m128_u64 + 4) = 0x6745230100000000i64;
  while ( 1 )
  {
    v16 = v14[3];
    if ( !v16 )
      break;
    if ( v16 <= v13 )
    {
      if ( sub_140018490(a1 + v16, Pa) )
      {
        v18 = Pa;
        v19 = -1i64;
        do
          ++v19;
        while ( *(Pa + v19) );
        if ( v19 > 4 )
        {
          nModuleExtension = *(Pa + v19 - 4);
          if ( nModuleExtension == 'xco.' || nModuleExtension == 'sys.' || nModuleExtension == 'lld.' )
            *(Pa + v19 - 4) = 0;
        }
        v21 = *v14;
        if ( v21 || (v21 = v14[4], v21) )
          v9 = (a1 + v21);
        if ( v9 && v9 < v15 )
        {
          if ( v44 == 32 )
          {
            v22 = v9;
            while ( 1 )
            {
              v23 = v22;
              v24 = *v22;
              if ( !*v22 )
                break;
              ++v22;
              v25 = !*v22 && !v14[8];
              v26 = *v23;
              if ( v24 >= 0 )
                v27 = sub_1400186B4(v18, (a1 + v26 + 2), v43);
              else
                v27 = sub_1400185A0(v18, v26, v43, v17, v25);
              if ( v27 )
              {
                v28 = -1i64;
                do
                  ++v28;
                while ( v43[v28] );
                sub_14002930C(&v40, v43, v28);
                ++v8;
              }
            }
          }
          else if ( v44 == 64 )
          {
            for ( i = v9; ; i = v31 )
            {
              v30 = *i;
              if ( !*i )
                break;
              v31 = i + 1;
              v32 = !i[1] && !v14[8];
              if ( v30 >= 0 )
                v33 = sub_1400186B4(v18, (a1 + v30 + 2), v43);
              else
                v33 = sub_1400185A0(v18, v30, v43, v17, v32);
              if ( v33 )
              {
                v34 = -1i64;
                do
                  ++v34;
                while ( v43[v34] );
                sub_14002930C(&v40, v43, v34);
                ++v8;
              }
            }
          }
        }
        EAC::Memory::ExFreePool(v18);
        v15 = v38;
      }
      v13 = v39;
    }
    v14 += 5;
  }
  if ( v8 )
  {
    sub_1400293C8(&v40, v45);
    if ( v47 )
      *v47 = v8;
    v36 = 1;
  }
  return v36;
}

