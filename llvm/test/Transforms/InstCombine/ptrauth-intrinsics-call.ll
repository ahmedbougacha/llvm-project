; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

define i32 @test_ptrauth_call_resign(ptr %p) {
; CHECK-LABEL: @test_ptrauth_call_resign(
; CHECK-NEXT:    [[V3:%.*]] = call i32 [[P:%.*]]() [ "ptrauth"(i32 0, i64 1234) ]
; CHECK-NEXT:    ret i32 [[V3]]
;
  %v0 = ptrtoint ptr %p to i64
  %v1 = call i64 @llvm.ptrauth.resign(i64 %v0, i32 0, i64 1234, i32 2, i64 5678)
  %v2 = inttoptr i64 %v1 to ptr
  %v3 = call i32 %v2() [ "ptrauth"(i32 2, i64 5678) ]
  ret i32 %v3
}

define i32 @test_ptrauth_call_resign_blend(ptr %pp) {
; CHECK-LABEL: @test_ptrauth_call_resign_blend(
; CHECK-NEXT:    [[V01:%.*]] = load ptr, ptr [[PP:%.*]], align 8
; CHECK-NEXT:    [[V6:%.*]] = call i32 [[V01]]() [ "ptrauth"(i32 0, i64 1234) ]
; CHECK-NEXT:    ret i32 [[V6]]
;
  %v0 = load ptr, ptr %pp, align 8
  %v1 = ptrtoint ptr %pp to i64
  %v2 = ptrtoint ptr %v0 to i64
  %v3 = call i64 @llvm.ptrauth.blend(i64 %v1, i64 5678)
  %v4 = call i64 @llvm.ptrauth.resign(i64 %v2, i32 0, i64 1234, i32 1, i64 %v3)
  %v5 = inttoptr i64 %v4 to ptr
  %v6 = call i32 %v5() [ "ptrauth"(i32 1, i64 %v3) ]
  ret i32 %v6
}

define i32 @test_ptrauth_call_resign_blend_2(ptr %pp) {
; CHECK-LABEL: @test_ptrauth_call_resign_blend_2(
; CHECK-NEXT:    [[V01:%.*]] = load ptr, ptr [[PP:%.*]], align 8
; CHECK-NEXT:    [[V1:%.*]] = ptrtoint ptr [[PP]] to i64
; CHECK-NEXT:    [[V3:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[V1]], i64 5678)
; CHECK-NEXT:    [[V6:%.*]] = call i32 [[V01]]() [ "ptrauth"(i32 1, i64 [[V3]]) ]
; CHECK-NEXT:    ret i32 [[V6]]
;
  %v0 = load ptr, ptr %pp, align 8
  %v1 = ptrtoint ptr %pp to i64
  %v2 = ptrtoint ptr %v0 to i64
  %v3 = call i64 @llvm.ptrauth.blend(i64 %v1, i64 5678)
  %v4 = call i64 @llvm.ptrauth.resign(i64 %v2, i32 1, i64 %v3, i32 0, i64 1234)
  %v5 = inttoptr i64 %v4 to ptr
  %v6 = call i32 %v5() [ "ptrauth"(i32 0, i64 1234) ]
  ret i32 %v6
}

define i32 @test_ptrauth_call_auth(ptr %p) {
; CHECK-LABEL: @test_ptrauth_call_auth(
; CHECK-NEXT:    [[V3:%.*]] = call i32 [[P:%.*]]() [ "ptrauth"(i32 2, i64 5678) ]
; CHECK-NEXT:    ret i32 [[V3]]
;
  %v0 = ptrtoint ptr %p to i64
  %v1 = call i64 @llvm.ptrauth.auth(i64 %v0, i32 2, i64 5678)
  %v2 = inttoptr i64 %v1 to i32()*
  %v3 = call i32 %v2()
  ret i32 %v3
}

define i32 @test_ptrauth_call_sign(ptr %p) {
; CHECK-LABEL: @test_ptrauth_call_sign(
; CHECK-NEXT:    [[V3:%.*]] = call i32 [[P:%.*]]()
; CHECK-NEXT:    ret i32 [[V3]]
;
  %v0 = ptrtoint ptr %p to i64
  %v1 = call i64 @llvm.ptrauth.sign(i64 %v0, i32 2, i64 5678)
  %v2 = inttoptr i64 %v1 to ptr
  %v3 = call i32 %v2() [ "ptrauth"(i32 2, i64 5678) ]
  ret i32 %v3
}

define i32 @test_ptrauth_call_sign_otherbundle(ptr %p) {
; CHECK-LABEL: @test_ptrauth_call_sign_otherbundle(
; CHECK-NEXT:    [[V3:%.*]] = call i32 [[P:%.*]]() [ "somebundle"(ptr null), "otherbundle"(i64 0) ]
; CHECK-NEXT:    ret i32 [[V3]]
;
  %v0 = ptrtoint ptr %p to i64
  %v1 = call i64 @llvm.ptrauth.sign(i64 %v0, i32 2, i64 5678)
  %v2 = inttoptr i64 %v1 to ptr
  %v3 = call i32 %v2() [ "somebundle"(ptr null), "ptrauth"(i32 2, i64 5678), "otherbundle"(i64 0) ]
  ret i32 %v3
}

declare i64 @llvm.ptrauth.sign(i64, i32, i64)
declare i64 @llvm.ptrauth.resign(i64, i32, i64, i32, i64)
declare i64 @llvm.ptrauth.blend(i64, i64)
