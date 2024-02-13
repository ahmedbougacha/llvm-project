// RUN: %clang_cc1 -triple arm64-apple-ios -fptrauth-intrinsics -emit-llvm %s  -o - | FileCheck %s

extern int external;

// CHECK: [[SIGNED1:@.*]] = private constant { ptr, i32, i64, i64 } { ptr @external, i32 0, i64 0, i64 26 }, section "llvm.ptrauth", align 8
// CHECK: @ptr1 = global ptr [[SIGNED1]]
void *ptr1 = __builtin_ptrauth_sign_constant(&external, 0, 26);

// CHECK: @ptr2 = global ptr [[SIGNED2:@.*]],
// CHECK: [[SIGNED2]] = private constant { ptr, i32, i64, i64 } { ptr @external, i32 2, i64 ptrtoint (ptr @ptr2 to i64), i64 26 }, section "llvm.ptrauth", align 8
void *ptr2 = __builtin_ptrauth_sign_constant(&external, 2, __builtin_ptrauth_blend_discriminator(&ptr2, 26));

// CHECK: [[SIGNED3:@.*]] = private constant { ptr, i32, i64, i64 } { ptr @external, i32 2, i64 0, i64 1234 }, section "llvm.ptrauth", align 8
// CHECK: @ptr3 = global ptr null
void *ptr3;

void test_sign_constant_code() {
// CHECK-LABEL: define void @test_sign_constant_code()
// CHECK-NEXT:  entry:
// CHECK-NEXT:    store ptr @external.ptrauth.2, ptr @ptr3, align 8
// CHECK-NEXT:    ret void
  ptr3 = __builtin_ptrauth_sign_constant(&external, 2, 1234);
}
