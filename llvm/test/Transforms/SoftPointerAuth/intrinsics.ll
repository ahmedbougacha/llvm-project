; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=soft-ptrauth -S | FileCheck %s

target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.12.0"

%struct.__block_descriptor = type { i64, i64 }
%struct.__block_literal_generic = type { ptr, i32, i32, ptr, ptr }

@blockptr = common global ptr null, align 8

define internal void @test1() {
; CHECK-LABEL: @test1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[BLOCK:%.*]] = load ptr, ptr @blockptr, align 8
; CHECK-NEXT:    [[FNPTR_ADDR:%.*]] = getelementptr inbounds [[STRUCT___BLOCK_LITERAL_GENERIC:%.*]], ptr [[BLOCK]], i32 0, i32 3
; CHECK-NEXT:    [[FNPTR:%.*]] = load ptr, ptr [[FNPTR_ADDR]], align 8
; CHECK-NEXT:    [[DISCRIMINATOR:%.*]] = ptrtoint ptr [[FNPTR_ADDR]] to i64
; CHECK-NEXT:    [[TMP0:%.*]] = call ptr @__ptrauth_auth(ptr [[FNPTR]], i32 1, i64 [[DISCRIMINATOR]]) #[[ATTR0:[0-9]+]]
; CHECK-NEXT:    call void [[TMP0]](ptr [[FNPTR_ADDR]])
; CHECK-NEXT:    ret void
;
entry:
  %block = load ptr, ptr @blockptr, align 8
  %fnptr_addr = getelementptr inbounds %struct.__block_literal_generic, ptr %block, i32 0, i32 3
  %fnptr = load ptr, ptr %fnptr_addr, align 8
  %discriminator = ptrtoint ptr %fnptr_addr to i64
  call void %fnptr(ptr %fnptr_addr) [ "ptrauth"(i32 1, i64 %discriminator) ]
  ret void
}
