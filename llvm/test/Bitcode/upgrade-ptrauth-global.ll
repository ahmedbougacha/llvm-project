; RUN: llvm-as < %s | llvm-dis | FileCheck %s

@var = global i32 0

@var.auth1 = constant { i8*, i32, i64, i64 } { i8* bitcast(i32* @var to i8*),
                                               i32 0,
                                               i64 0,
                                               i64 1234 }, section "llvm.ptrauth"
@var_auth = global i32* bitcast({i8*, i32, i64, i64}* @var.auth1 to i32*)
; CHECK: @var_auth = global ptr ptrauth (ptr @var, i32 0, ptr null, i64 1234)
