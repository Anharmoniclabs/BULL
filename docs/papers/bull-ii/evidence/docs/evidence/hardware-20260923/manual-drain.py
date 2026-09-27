import ctypes as C,json
lib=C.CDLL('libhidapi-libusb.so.0')
lib.hid_open.argtypes=[C.c_ushort,C.c_ushort,C.c_wchar_p];lib.hid_open.restype=C.c_void_p
lib.hid_read_timeout.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t,C.c_int];lib.hid_close.argtypes=[C.c_void_p]
lib.hid_init();h=lib.hid_open(0xcafe,0x4010,None)
if not h: raise SystemExit('Diagnostic KB2040 unavailable')
count=0
try:
 for _ in range(16):
  buf=C.create_string_buffer(64);n=lib.hid_read_timeout(h,buf,64,100)
  if n==0: break
  if n!=64 or buf.raw[:11]!=b'BULL-DIAG-3' or buf.raw[11]!=0: raise SystemExit('Unexpected diagnostic packet; stopped')
  count+=1
 else: raise SystemExit('Diagnostic receive queue did not settle')
 print(json.dumps({'queued_diagnostic_replies_drained':count,'approval_available':False}))
finally: lib.hid_close(h);lib.hid_exit()
