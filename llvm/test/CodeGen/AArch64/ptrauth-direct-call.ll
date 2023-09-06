; RUN: llc < %s -mtriple arm64e-apple-darwin -global-isel=0            | FileCheck %s
; RUN: llc < %s -mtriple arm64e-apple-darwin -global-isel=0 -fast-isel | FileCheck %s
; RUN: llc < %s -mtriple arm64e-apple-darwin -global-isel=1 -global-isel-abort=1 -verify-machineinstrs | FileCheck %s

target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"

; Check code references.

; CHECK-LABEL: _test_direct_call_bitcast:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_bitcast() #0 {
  %tmp0 = bitcast ptr @f.ptrauth.ia.42 to ptr
  %tmp1 = call i32 %tmp0() [ "ptrauth"(i32 0, i64 42) ]
  ret i32 %tmp1
}

; CHECK-LABEL: _test_direct_call:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call() #0 {
  %tmp0 = call i32 @f.ptrauth.ia.42() [ "ptrauth"(i32 0, i64 42) ]
  ret i32 %tmp0
}

; CHECK-LABEL: _test_direct_call_mismatch:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT: Lloh{{.*}}:
; CHECK-NEXT:   adrp x16, _f@GOTPAGE
; CHECK-NEXT: Lloh{{.*}}:
; CHECK-NEXT:   ldr x16, [x16, _f@GOTPAGEOFF]
; CHECK-NEXT:   mov x17, #42
; CHECK-NEXT:   pacia x16, x17
; CHECK-NEXT:   mov x8, x16
; CHECK-NEXT:   mov x17, #42
; CHECK-NEXT:   blrab x8, x17
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_mismatch() #0 {
  %tmp0 = call i32 @f.ptrauth.ia.42() [ "ptrauth"(i32 1, i64 42) ]
  ret i32 %tmp0
}

; CHECK-LABEL: _test_direct_call_addr:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_addr() #0 {
  %tmp0 = call i32 @f.ptrauth.ib.0.addr() [ "ptrauth"(i32 1, i64 ptrtoint (ptr @f.ref.ib.0.addr to i64)) ]
  ret i32 %tmp0
}

; CHECK-LABEL: _test_direct_call_addr_blend:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_addr_blend() #0 {
  %tmp0 = call i64 @llvm.ptrauth.blend(i64 ptrtoint (ptr @f.ref.ib.42.addr to i64), i64 42)
  %tmp1 = call i32 @f.ptrauth.ib.42.addr() [ "ptrauth"(i32 1, i64 %tmp0) ]
  ret i32 %tmp1
}

; CHECK-LABEL: _test_direct_call_addr_gep_different_index_types:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_addr_gep_different_index_types() #0 {
  %tmp0 = call i32 bitcast ({ i8*, i32, i64, i64 }* @f_struct.ptrauth.ib.0.addr to i32 ()*)() [ "ptrauth"(i32 1, i64 ptrtoint (i8** getelementptr ({ i8* }, { i8* }* @f_struct.ref.ib.0.addr, i32 0, i32 0) to i64)) ]
  ret i32 %tmp0
}

; CHECK-LABEL: _test_direct_call_addr_blend_gep_different_index_types:
; CHECK-NEXT: ; %bb.0:
; CHECK-NEXT:   stp x29, x30, [sp, #-16]!
; CHECK-NEXT:   bl _f
; CHECK-NEXT:   ldp x29, x30, [sp], #16
; CHECK-NEXT:   ret
define i32 @test_direct_call_addr_blend_gep_different_index_types() #0 {
  %tmp0 = call i64 @llvm.ptrauth.blend(i64 ptrtoint (i8** getelementptr ({ i8* }, { i8* }* @f_struct.ref.ib.123.addr, i32 0, i32 0) to i64), i64 123)
  %tmp1 = call i32 bitcast ({ i8*, i32, i64, i64 }* @f_struct.ptrauth.ib.123.addr to i32 ()*)() [ "ptrauth"(i32 1, i64 %tmp0) ]
  ret i32 %tmp1
}

declare i64 @llvm.ptrauth.auth(i64, i32, i64) #0
declare i64 @llvm.ptrauth.blend(i64, i64) #0

attributes #0 = { nounwind }

; Check global references.

declare void @f()

; CHECK-LABEL:   .section __DATA,__const
; CHECK-NEXT:    .globl _f.ref.ia.42
; CHECK-NEXT:    .p2align 3
; CHECK-NEXT:  _f.ref.ia.42:
; CHECK-NEXT:    .quad _f@AUTH(ia,42)

@f.ptrauth.ia.42 = private constant { ptr, i32, i64, i64 } { ptr @f, i32 0, i64 0, i64 42 }, section "llvm.ptrauth"

@f.ref.ia.42 = constant ptr @f.ptrauth.ia.42

; CHECK-LABEL:   .globl _f.ref.ib.42.addr
; CHECK-NEXT:    .p2align 3
; CHECK-NEXT:  _f.ref.ib.42.addr:
; CHECK-NEXT:    .quad _f@AUTH(ib,42,addr)

@f.ptrauth.ib.42.addr = private constant { ptr, i32, i64, i64 } { ptr @f, i32 1, i64 ptrtoint (ptr @f.ref.ib.42.addr to i64), i64 42 }, section "llvm.ptrauth"

@f.ref.ib.42.addr = constant ptr @f.ptrauth.ib.42.addr

; CHECK-LABEL:   .globl _f.ref.ib.0.addr
; CHECK-NEXT:    .p2align 3
; CHECK-NEXT:  _f.ref.ib.0.addr:
; CHECK-NEXT:    .quad _f@AUTH(ib,0,addr)

@f.ptrauth.ib.0.addr = private constant { ptr, i32, i64, i64 } { ptr @f, i32 1, i64 ptrtoint (ptr @f.ref.ib.0.addr to i64), i64 0 }, section "llvm.ptrauth"

@f.ref.ib.0.addr = constant ptr @f.ptrauth.ib.0.addr

; CHECK-LABEL:   .globl _f_struct.ref.ib.0.addr
; CHECK-NEXT:    .p2align 3
; CHECK-NEXT:  _f_struct.ref.ib.0.addr:
; CHECK-NEXT:    .quad _f@AUTH(ib,0,addr)

@f_struct.ptrauth.ib.0.addr = private constant { ptr, i32, i64, i64 } { ptr @f, i32 1, i64 ptrtoint (ptr getelementptr ({ ptr }, ptr @f_struct.ref.ib.0.addr, i64 0, i32 0) to i64), i64 0 }, section "llvm.ptrauth"

@f_struct.ref.ib.0.addr = constant { ptr } { ptr @f_struct.ptrauth.ib.0.addr }

; CHECK-LABEL:   .globl _f_struct.ref.ib.123.addr
; CHECK-NEXT:    .p2align 3
; CHECK-NEXT:  _f_struct.ref.ib.123.addr:
; CHECK-NEXT:    .quad _f@AUTH(ib,123,addr)

@f_struct.ptrauth.ib.123.addr = private constant { ptr, i32, i64, i64 } { ptr @f, i32 1, i64 ptrtoint (ptr getelementptr ({ ptr }, ptr @f_struct.ref.ib.123.addr, i64 0, i32 0) to i64), i64 123 }, section "llvm.ptrauth"

@f_struct.ref.ib.123.addr = constant { ptr } { ptr @f_struct.ptrauth.ib.123.addr }
