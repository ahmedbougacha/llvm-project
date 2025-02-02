// RUN: %clang_cc1 %s -triple arm64e-apple-ios13 -fptrauth-calls -fptrauth-intrinsics -emit-llvm -o- | FileCheck %s
// RUN: %clang_cc1 %s -triple aarch64-linux-gnu -fptrauth-calls -fptrauth-intrinsics -emit-llvm -o- | FileCheck %s

typedef void (*fptr_t)(void);

char *cptr;
void (*fptr)(void);

typedef struct __attribute__((ptrauth_struct(0,42))) S {} S;
S *sptr;

// CHECK: define {{(dso_local )?}}void @test1
void test1() {
  // CHECK: [[LOAD:%.*]] = load ptr, ptr @cptr
  // CHECK: call void [[LOAD]]() [ "ptrauth"(i32 0, i64 0) ]
  // CHECK: ret void

  (*(fptr_t)cptr)();
}

// CHECK: define {{(dso_local )?}}i8 @test2
char test2() {
  return *(char *)fptr;
  // CHECK: [[LOAD:%.*]] = load ptr, ptr @fptr
  // CHECK: [[LOAD1:%.*]] = load i8, ptr [[LOAD]]
  // CHECK: ret i8 [[LOAD1]]
}

// CHECK-LABEL: define {{(dso_local )?}}void @test3
void test3() {
  (S *)fptr;
  // CHECK: [[LOAD:%.*]] = load ptr, ptr @fptr
  // CHECK: [[CMP:%.*]] = icmp ne ptr [[LOAD]], null

  // CHECK: [[TOINT:%.*]] = ptrtoint ptr [[LOAD]] to i64
  // CHECK: call i64 @llvm.ptrauth.resign(i64 [[TOINT]], i32 0, i64 0, i32 0, i64 42)
}
