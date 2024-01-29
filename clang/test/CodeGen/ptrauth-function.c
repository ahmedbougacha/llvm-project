// RUN: %clang_cc1 %s       -fptrauth-function-pointer-type-discrimination -triple arm64e-apple-ios13 -fptrauth-calls -fptrauth-intrinsics -disable-llvm-passes -emit-llvm -o- | FileCheck %s --check-prefix=CHECK --check-prefix=CHECKC
// RUN: %clang_cc1 -xc++ %s -fptrauth-function-pointer-type-discrimination -triple arm64e-apple-ios13 -fptrauth-calls -fptrauth-intrinsics -disable-llvm-passes -emit-llvm -o- | FileCheck %s --check-prefix=CHECK --check-prefix=CHECKCXX

#ifdef __cplusplus
extern "C" {
#endif

void f(void);
void f2(int);
void (*fptr)(void);
void *opaque;
unsigned long uintptr;

// CHECK: @test_constant_null = global ptr null
void (*test_constant_null)(int) = 0;

// CHECK: @test_constant_cast = global ptr ptrauth (ptr @f, i32 0, ptr null, i64 2712)
void (*test_constant_cast)(int) = (void (*)(int))f;

// CHECK: @test_opaque = global ptr ptrauth (ptr @f, i32 0, ptr null, i64 0)
void *test_opaque =
#ifdef __cplusplus
    (void *)
#endif
    (void (*)(int))(double (*)(double))f;

// CHECK: @test_intptr_t = global i64 ptrtoint (ptr ptrauth (ptr @f, i32 0, ptr null, i64 0) to i64)
unsigned long test_intptr_t = (unsigned long)f;

// CHECK: @test_through_long = global ptr ptrauth (ptr @f, i32 0, ptr null, i64 2712)
void (*test_through_long)(int) = (void (*)(int))(long)f;

// CHECK: @test_to_long = global i64 ptrtoint (ptr ptrauth (ptr @f, i32 0, ptr null, i64 0) to i64)
long test_to_long = (long)(double (*)())f;

#ifdef __cplusplus
struct ptr_member {
  void (*fptr_)(int) = 0;
};
ptr_member pm;
void (*test_member)() = (void (*)())pm.fptr_;

// CHECKCXX-LABEL: define internal void @__cxx_global_var_init
// CHECKCXX: call i64 @llvm.ptrauth.resign(i64 {{.*}}, i32 0, i64 2712, i32 0, i64 18983)
#endif


// CHECK-LABEL: define void @test_cast_to_opaque
void test_cast_to_opaque() {
  opaque = (void *)f;

  // CHECK: [[RESIGN_VAL:%.*]] = call i64 @llvm.ptrauth.resign(i64 ptrtoint (ptr ptrauth (ptr @f, i32 0, ptr null, i64 18983) to i64), i32 0, i64 18983, i32 0, i64 0)
  // CHECK: [[RESIGN_PTR:%.*]] = inttoptr i64 [[RESIGN_VAL]] to ptr
}

// CHECK-LABEL: define void @test_cast_from_opaque
void test_cast_from_opaque() {
  fptr = (void (*)(void))opaque;

  // CHECK: [[LOAD:%.*]] = load ptr, ptr @opaque
  // CHECK: [[CMP:%.*]] = icmp ne ptr [[LOAD]], null
  // CHECK: br i1 [[CMP]], label %[[RESIGN_LAB:.*]], label

  // CHECK: [[RESIGN_LAB]]:
  // CHECK: [[INT:%.*]] = ptrtoint ptr [[LOAD]] to i64
  // CHECK: [[RESIGN_INT:%.*]] = call i64 @llvm.ptrauth.resign(i64 [[INT]], i32 0, i64 0, i32 0, i64 18983)
}

// CHECK-LABEL: define void @test_cast_to_intptr
void test_cast_to_intptr() {
  uintptr = (unsigned long)fptr;

  // CHECK: [[ENTRY:.*]]:
  // CHECK: [[LOAD:%.*]] = load ptr, ptr @fptr
  // CHECK: [[CMP:%.*]] = icmp ne ptr [[LOAD]], null
  // CHECK: br i1 [[CMP]], label %[[RESIGN_LAB:.*]], label %[[RESIGN_CONT:.*]]

  // CHECK: [[RESIGN_LAB]]:
  // CHECK: [[INT:%.*]] = ptrtoint ptr [[LOAD]] to i64
  // CHECK: [[RESIGN_INT:%.*]] = call i64 @llvm.ptrauth.resign(i64 [[INT]], i32 0, i64 18983, i32 0, i64 0)
  // CHECK: [[RESIGN:%.*]] = inttoptr i64 [[RESIGN_INT]] to ptr
  // CHECK: br label %[[RESIGN_CONT]]

  // CHECK: [[RESIGN_CONT]]:
  // CHECK: phi ptr [ null, %[[ENTRY]] ], [ [[RESIGN]], %[[RESIGN_LAB]] ]
}

// CHECK-LABEL: define void @test_function_to_function_cast
void test_function_to_function_cast() {
  void (*fptr2)(int) = (void (*)(int))fptr;
  // CHECK: call i64 @llvm.ptrauth.resign(i64 {{.*}}, i32 0, i64 18983, i32 0, i64 2712)
}

// CHECK-LABEL: define void @test_call
void test_call() {
  fptr();
  // CHECK: call void %0() [ "ptrauth"(i32 0, i64 18983) ]
}

// CHECK-LABEL: define void @test_call_lvalue_cast
void test_call_lvalue_cast() {
  (*(void (*)(int))f)(42);

  // CHECK: entry:
  // CHECK-NEXT: [[RESIGN_VAL:%.*]] = call i64 @llvm.ptrauth.resign(i64 ptrtoint (ptr ptrauth (ptr @f, i32 0, ptr null, i64 18983) to i64), i32 0, i64 18983, i32 0, i64 2712)
  // CHECK-NEXT: [[RESIGN_INT:%.*]] = inttoptr i64 [[RESIGN]] to ptr
  // CHECK-NEXT: call void [[RESIGN_INT]](i32 noundef 42) [ "ptrauth"(i32 0, i64 2712) ]
}

#ifndef __cplusplus

void knr(param)
  int param;
{}

// CHECKC-LABEL: define void @test_knr
void test_knr() {
  void (*p)() = knr;
  p(0);

  // CHECKC: [[P:%.*]] = alloca ptr
  // CHECKC: store ptr ptrauth (ptr @knr, i32 0, ptr null, i64 18983), ptr [[P]]
  // CHECKC: [[LOAD:%.*]] = load ptr, ptr [[P]]
  // CHECKC: call void [[LOAD]](i32 noundef 0) [ "ptrauth"(i32 0, i64 18983) ]

  void *p2 = p;

  // CHECKC: call i64 @llvm.ptrauth.resign(i64 {{.*}}, i32 0, i64 18983, i32 0, i64 0)
}

// CHECKC-LABEL: define void @test_redeclaration
void test_redeclaration() {
  void redecl();
  void (*ptr)() = redecl;
  void redecl(int);
  void (*ptr2)(int) = redecl;
  ptr();
  ptr2(0);

  // CHECKC-NOT: call i64 @llvm.ptrauth.resign
  // CHECKC: call void {{.*}}() [ "ptrauth"(i32 0, i64 18983) ]
  // CHECKC: call void {{.*}}(i32 noundef 0) [ "ptrauth"(i32 0, i64 2712) ]
}

void knr2(param)
     int param;
{}

// CHECKC-LABEL: define void @test_redecl_knr
void test_redecl_knr() {
  void (*p)() = knr2;
  p();

  void knr2(int);

  void (*p2)(int) = knr2;
  p2(0);

  // CHECKC-NOT: call i64 @llvm.ptrauth.resign
  // CHECKC: call void {{.*}}() [ "ptrauth"(i32 0, i64 18983) ]
  // CHECKC: call void {{.*}}(i32 noundef 0) [ "ptrauth"(i32 0, i64 2712) ]
}

#endif

#ifdef __cplusplus
}
#endif
