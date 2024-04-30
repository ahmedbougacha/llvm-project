// RUN: %clang_cc1 -triple arm64-apple-ios -fptrauth-calls -fptrauth-intrinsics -fblocks -emit-llvm %s  -o - | FileCheck %s

void (^blockptr)(void);

// CHECK: [[GLOBAL_BLOCK_1:@.*]] = internal constant { ptr, i32, i32, ptr, ptr } { ptr @_NSConcreteGlobalBlock, i32 1342177280, i32 0, ptr ptrauth (ptr {{@.*}}, i32 0, ptr getelementptr inbounds ({ ptr, i32, i32, ptr, ptr }, ptr [[GLOBAL_BLOCK_1]], i32 0, i32 3), i64 0), ptr {{@.*}}
void (^globalblock)(void) = ^{};

// CHECK-LABEL: define void @test_block_call()
void test_block_call() {
  // CHECK:      [[T0:%.*]] = load ptr, ptr @blockptr,
  // CHECK-NEXT: [[FNADDR:%.*]] = getelementptr inbounds {{.*}}, ptr [[T0]], i32 0, i32 3
  // CHECK-NEXT: [[T1:%.*]] = load ptr, ptr [[FNADDR]],
  // CHECK-NEXT: [[DISC:%.*]] = ptrtoint ptr [[FNADDR]] to i64
  // CHECK-NEXT: call void [[T1]](ptr noundef [[T0]]) [ "ptrauth"(i32 0, i64 [[DISC]]) ]
  blockptr();
}

void use_block(int (^)(void));

// CHECK-LABEL: define void @test_block_literal(
void test_block_literal(int i) {
  // CHECK:      [[I:%.*]] = alloca i32,
  // CHECK-NEXT: [[BLOCK:%.*]] = alloca [[BLOCK_T:.*]], align
  // CHECK:      [[FNPTRADDR:%.*]] = getelementptr inbounds [[BLOCK_T]], ptr [[BLOCK]], i32 0, i32 3
  // CHECK-NEXT: [[DISCRIMINATOR:%.*]] = ptrtoint ptr [[FNPTRADDR]] to i64
  // CHECK-NEXT: [[SIGNED:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr {{@.*}} to i64), i32 0, i64 [[DISCRIMINATOR]])
  // CHECK-NEXT: [[T0:%.*]] = inttoptr i64 [[SIGNED]] to ptr
  // CHECK-NEXT: store ptr [[T0]], ptr [[FNPTRADDR]]
  use_block(^{return i;});
}

struct A {
  int value;
};
struct A *createA(void);

// CHECK-LABEL: define void @test_block_nonaddress_capture(
void test_block_nonaddress_capture() {
  // CHECK: [[VAR:%.*]] = alloca ptr,
  // CHECK: [[BLOCK:%.*]] = alloca
  //   flags - no copy/dispose required
  // CHECK: store i32 1073741824, ptr
  // CHECK: [[CAPTURE:%.*]] = getelementptr inbounds {{.*}} [[BLOCK]], i32 0, i32 5
  // CHECK: [[LOAD:%.*]] = load ptr, ptr [[VAR]],
  // CHECK: store ptr [[LOAD]], ptr [[CAPTURE]]
  struct A * __ptrauth(1, 0, 15) ptr = createA();
  use_block(^{ return ptr->value; });
}
// CHECK-LABEL: define internal i32 @__test_block_nonaddress_capture_block_invoke
// CHECK: call i64 @llvm.ptrauth.auth(i64 {{%.*}}, i32 1, i64 15)

// CHECK-LABEL: define void @test_block_address_capture(
void test_block_address_capture() {
  // CHECK: [[VAR:%.*]] = alloca ptr,
  // CHECK: [[BLOCK:%.*]] = alloca
  //   flags - copy/dispose required
  // CHECK: store i32 1107296256, ptr
  // CHECK: [[CAPTURE:%.*]] = getelementptr inbounds {{.*}} [[BLOCK]], i32 0, i32 5
  // CHECK: [[LOAD:%.*]] = load ptr, ptr [[VAR]],
  // CHECK: [[T0:%.*]] = ptrtoint ptr [[VAR]] to i64
  // CHECK: [[OLDDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 30)
  // CHECK: [[T0:%.*]] = ptrtoint ptr [[CAPTURE]] to i64
  // CHECK: [[NEWDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 30)
  // CHECK: [[T0:%.*]] = icmp ne ptr [[LOAD]], null
  // CHECK: br i1 [[T0]]
  // CHECK: [[T0:%.*]] = ptrtoint ptr [[LOAD]] to i64
  // CHECK: [[T1:%.*]] = call i64 @llvm.ptrauth.resign(i64 [[T0]], i32 1, i64 [[OLDDISC]], i32 1, i64 [[NEWDISC]])
  // CHECK: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
  // CHECK: [[T0:%.*]] = phi
  // CHECK: store ptr [[T0]], ptr [[CAPTURE]]
  struct A * __ptrauth(1, 1, 30) ptr = createA();
  use_block(^{ return ptr->value; });
}
// CHECK-LABEL: define internal i32 @__test_block_address_capture_block_invoke
// CHECK: call i64 @llvm.ptrauth.auth(i64 {{%.*}}, i32 1, i64 {{%.*}})

// CHECK: linkonce_odr hidden void @__copy_helper_block_8_32p1d30(
// CHECK: [[OLDSLOT:%.*]] = getelementptr inbounds {{.*}} {{.*}}, i32 0, i32 5
// CHECK: [[NEWSLOT:%.*]] = getelementptr inbounds {{.*}} {{.*}}, i32 0, i32 5
// CHECK: [[LOAD:%.*]] = load ptr, ptr [[OLDSLOT]],
// CHECK: [[T0:%.*]] = ptrtoint ptr [[OLDSLOT]] to i64
// CHECK: [[OLDDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 30)
// CHECK: [[T0:%.*]] = ptrtoint ptr [[NEWSLOT]] to i64
// CHECK: [[NEWDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 30)
// CHECK: [[T0:%.*]] = icmp ne ptr [[LOAD]], null
// CHECK: br i1 [[T0]]
// CHECK: [[T0:%.*]] = ptrtoint ptr [[LOAD]] to i64
// CHECK: [[T1:%.*]] = call i64 @llvm.ptrauth.resign(i64 [[T0]], i32 1, i64 [[OLDDISC]], i32 1, i64 [[NEWDISC]])
// CHECK: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
// CHECK: [[T0:%.*]] = phi
// CHECK: store ptr [[T0]], ptr [[NEWSLOT]]

// CHECK-LABEL: define void @test_block_nonaddress_byref_capture(
void test_block_nonaddress_byref_capture() {
  //   flags - no copy/dispose required for byref
  // CHECK: store i32 0,
  // CHECK: call ptr @createA()
  //   flags - copy/dispose required for block (because it captures byref)
  // CHECK: store i32 1107296256,
  __block struct A * __ptrauth(1, 0, 45) ptr = createA();
  use_block(^{ return ptr->value; });
}

// CHECK-LABEL: define void @test_block_address_byref_capture(
void test_block_address_byref_capture() {
  // CHECK: [[BYREF:%.*]] = alloca [[BYREF_T:.*]], align
  // CHECK: [[BLOCK:%.*]] = alloca
  //   flags - byref requires copy/dispose
  // CHECK: store i32 33554432,
  // CHECK: store i32 48,
  // CHECK: [[COPY_HELPER_FIELD:%.*]] = getelementptr inbounds [[BYREF_T]], ptr [[BYREF]], i32 0, i32 4
  // CHECK: [[T0:%.*]] = ptrtoint ptr [[COPY_HELPER_FIELD]] to i64
  // CHECK: [[T1:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr @__Block_byref_object_copy_ to i64), i32 0, i64 [[T0]])
  // CHECK: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
  // CHECK: store ptr [[T2]], ptr [[COPY_HELPER_FIELD]], align
  // CHECK: [[DISPOSE_HELPER_FIELD:%.*]] = getelementptr inbounds [[BYREF_T]], ptr [[BYREF]], i32 0, i32 5
  // CHECK: [[T0:%.*]] = ptrtoint ptr [[DISPOSE_HELPER_FIELD]] to i64
  // CHECK: [[T1:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr @__Block_byref_object_dispose_ to i64), i32 0, i64 [[T0]])
  // CHECK: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
  // CHECK: store ptr [[T2]], ptr [[DISPOSE_HELPER_FIELD]], align
  //   flags - copy/dispose required
  // CHECK: store i32 1107296256, ptr
  __block struct A * __ptrauth(1, 1, 60) ptr = createA();
  use_block(^{ return ptr->value; });
}
// CHECK-LABEL: define internal void @__Block_byref_object_copy_
// CHECK: [[NEWSLOT:%.*]] = getelementptr inbounds {{.*}} {{.*}}, i32 0, i32 6
// CHECK: [[OLDSLOT:%.*]] = getelementptr inbounds {{.*}} {{.*}}, i32 0, i32 6
// CHECK: [[LOAD:%.*]] = load ptr, ptr [[OLDSLOT]],
// CHECK: [[T0:%.*]] = ptrtoint ptr [[OLDSLOT]] to i64
// CHECK: [[OLDDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 60)
// CHECK: [[T0:%.*]] = ptrtoint ptr [[NEWSLOT]] to i64
// CHECK: [[NEWDISC:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[T0]], i64 60)
// CHECK: [[T0:%.*]] = icmp ne ptr [[LOAD]], null
// CHECK: br i1 [[T0]]
// CHECK: [[T0:%.*]] = ptrtoint ptr [[LOAD]] to i64
// CHECK: [[T1:%.*]] = call i64 @llvm.ptrauth.resign(i64 [[T0]], i32 1, i64 [[OLDDISC]], i32 1, i64 [[NEWDISC]])
// CHECK: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
// CHECK: [[T0:%.*]] = phi
// CHECK: store ptr [[T0]], ptr [[NEWSLOT]]
