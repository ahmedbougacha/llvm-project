; RUN: llvm-as < %s | llvm-dis | FileCheck %s

@var = global i32 0

@var.ptrauth1 = constant { i8*, i32, i64, i64 } { i8* bitcast(i32* @var to i8*),
                                               i32 0,
                                               i64 0,
                                               i64 1234 }, section "llvm.ptrauth"
@var_auth1 = global i32* bitcast({i8*, i32, i64, i64}* @var.ptrauth1 to i32*)
; CHECK: @var_auth1 = global ptr ptrauth (ptr @var, i32 0, i64 1234)


@dummy_addrdisc = global i64* null

@var.ptrauth2 = constant { i8*, i32, i64, i64 } { i8* bitcast(i32* @var to i8*),
                                                  i32 2,
                                                  i64 ptrtoint(i64** @dummy_addrdisc to i64),
                                                  i64 5678 }, section "llvm.ptrauth"
@var_auth2 = global i32* bitcast({i8*, i32, i64, i64}* @var.ptrauth2 to i32*)
; CHECK: @var_auth2 = global ptr ptrauth (ptr @var, i32 2, i64 5678, ptr @dummy_addrdisc)
