// RUN: %clang_cc1 -triple arm64-apple-ios -fptrauth-calls -fptrauth-returns -fptrauth-intrinsics -emit-llvm -std=c++11 -fexceptions -fcxx-exceptions -o - %s | FileCheck %s

// CHECK: @_Z1fv.ptrauth = private constant { ptr, i32, i64, i64 } { ptr @_Z1fv, i32 0, i64 0, i64 0 },

void f(void);
auto &f_ref = f;

// CHECK-LABEL: define void @_Z1gv(
// CHECK: call void @_Z1fv.ptrauth() [ "ptrauth"(i32 0, i64 0) ]

void g() { f_ref(); }

void foo1();

void test_terminate() noexcept {
  foo1();
}

// CHECK: define void @_ZSt9terminatev() #[[ATTR4:.*]] {

namespace std {
  void terminate() noexcept {
  }
}

// CHECK: attributes #[[ATTR4]] = {{{.*}}"ptrauth-calls" "ptrauth-returns"{{.*}}}
