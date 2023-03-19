
### Decrypt config using RC4

Pseudocode
```c++
void *__thiscall remcos_load_config_from_rsrc_and_decrypt_using_rc4(void *remcos_dec_config)
{                                                                                               
  HRSRC resource_size; // eax@1 MAPDST
  SIZE_T rc4_key_len; // ebp@1
  char *rc4_key; // ebx@1
  char *p_rc4_key; // eax@1
  char *enc_config_data; // esi@1
  int enc_config_size; // [sp+10h] [bp-424h]@1 MAPDST
  char v12; // [sp+18h] [bp-41Ch]@1
  char rc4_sbox; // [sp+30h] [bp-404h]@1

  enc_config_size = 0;
  resource_size = mw_remcos_load_enc_config_from_rsrc(&enc_config_size);
  rc4_key_len = *(_BYTE *)enc_config_size;      // 0xE5
  rc4_key = (char *)remcos_malloc(rc4_key_len);
  remcos_memcpy(rc4_key, (const void *)(enc_config_size + 1), rc4_key_len);
  p_rc4_key = (char *)sub_402097(&v12, rc4_key, rc4_key_len);
  sub_401FC2(&g_p_rc4_key, p_rc4_key);
  sub_401FB8(&v12);
  enc_config_size = (int)resource_size + -1u - rc4_key_len;
  enc_config_data = (char *)remcos_malloc(enc_config_size);
  remcos_memcpy(enc_config_data, (const void *)(rc4_key_len + enc_config_size + 1), enc_config_size);
  remcos_rc4_KSA_wrap(&rc4_sbox, rc4_key, rc4_key_len);
  remcos_rc4_PRGA_wrap(&rc4_sbox, remcos_dec_config, enc_config_data, enc_config_size);
  sub_438F3B(enc_config_data);
  return remcos_dec_config;
}                                             
```
