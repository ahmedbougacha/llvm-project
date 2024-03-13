// RUN: %clang_cc1 -fptrauth-function-pointer-type-discrimination -triple arm64-apple-ios -fptrauth-calls -fcxx-exceptions -emit-llvm -no-enable-noundef-analysis %s -o - | FileCheck %s

class Foo {
 public:
  ~Foo() {
  }
};

void f() {
  throw Foo();
}

// __cxa_throw is defined to take its destructor as "void (*)(void *)" in the ABI.
void __cxa_throw(void *exception, void *, void (*dtor)(void *)) {
  dtor(exception);
}

// CHECK: define void @_Z1fv()
// CHECK:  call void @__cxa_throw(ptr %{{.*}}, ptr @_ZTI3Foo, ptr ptrauth (ptr @_ZN3FooD1Ev, i32 0, ptr null, i64 [[DISC:10942]]))

// CHECK: call void {{%.*}}(ptr {{%.*}}) [ "ptrauth"(i32 0, i64 [[DISC]]) ]
