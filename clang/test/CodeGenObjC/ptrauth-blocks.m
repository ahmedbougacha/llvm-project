// RUN: %clang_cc1 -fptrauth-calls -fptrauth-objc-isa-mode=sign-and-strip -fobjc-arc -fblocks -fobjc-runtime=ios-7 -triple arm64-apple-ios -emit-llvm %s  -o - | FileCheck %s
// RUN: %clang_cc1 -fptrauth-calls -fptrauth-objc-isa-mode=sign-and-auth  -fobjc-arc -fblocks -fobjc-runtime=ios-7 -triple arm64-apple-ios -emit-llvm %s  -o - | FileCheck %s

void (^blockptr)(void);


// CHECK: [[GLOBAL_BLOCK_1:@.*]] = internal constant { ptr, i32, i32, ptr, ptr } { ptr ptrauth (ptr @_NSConcreteGlobalBlock, i32 2, i64 27361, ptr [[GLOBAL_BLOCK_1]]), i32 1342177280, i32 0, ptr ptrauth (ptr {{@.*}}, i32 0, i64 0, ptr getelementptr inbounds ({ ptr, i32, i32, ptr, ptr }, ptr [[GLOBAL_BLOCK_1]], i32 0, i32 3)),
void (^globalblock)(void) = ^{};

// CHECK: [[COPYDISPOSE_DESCRIPTOR:@.*]] = linkonce_odr hidden unnamed_addr constant { i64, i64, ptr, ptr, ptr, i64 } { i64 0, i64 40, ptr ptrauth (ptr {{@.*}}, i32 0, i64 0, ptr getelementptr inbounds ({ i64, i64, ptr, ptr, ptr, i64 }, ptr [[COPYDISPOSE_DESCRIPTOR]], i32 0, i32 2)), ptr ptrauth (ptr {{@.*}}, i32 0, i64 0, ptr getelementptr inbounds ({ i64, i64, ptr, ptr, ptr, i64 }, ptr [[COPYDISPOSE_DESCRIPTOR]], i32 0, i32 3)),

@interface A
- (int) count;
@end

// CHECK-LABEL: define void @test_block_call()
void test_block_call() {
  // CHECK:      [[BLOCK:%.*]] = load ptr, ptr @blockptr,
  // CHECK-NEXT: [[FNADDR:%.*]] = getelementptr inbounds nuw {{.*}}, ptr [[BLOCK]], i32 0, i32 3
  // CHECK-NEXT: [[T0:%.*]] = load ptr, ptr [[FNADDR]],
  // CHECK-NEXT: [[DISC:%.*]] = ptrtoint ptr [[FNADDR]] to i64
  // CHECK-NEXT: call void [[T0]](ptr noundef [[BLOCK]]) [ "ptrauth"(i32 0, i64 [[DISC]]) ]
  blockptr();
}

void use_block(int (^)(void));

// CHECK-LABEL: define void @test_block_literal(
void test_block_literal(int i) {
  // CHECK:      [[I:%.*]] = alloca i32,
  // CHECK-NEXT: [[BLOCK:%.*]] = alloca [[BLOCK_T:.*]], align
  // CHECK:      [[ISAPTRADDR:%.*]] = getelementptr inbounds nuw [[BLOCK_T]], ptr [[BLOCK]], i32 0, i32 0
  // CHECK-NEXT: [[ISAPTRADDR_I:%.*]] = ptrtoint ptr [[ISAPTRADDR]] to i64
  // CHECK-NEXT: [[ISADISCRIMINATOR:%.*]] = call i64 @llvm.ptrauth.blend(i64 [[ISAPTRADDR_I]], i64 27361)
  // CHECK-NEXT: [[SIGNEDISA:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr @_NSConcreteStackBlock to i64), i32 2, i64 [[ISADISCRIMINATOR]])
  // CHECK-NEXT: [[SIGNEDISAPTR:%.*]] = inttoptr i64 [[SIGNEDISA]] to ptr
  // CHECK-NEXT: store ptr [[SIGNEDISAPTR]], ptr [[ISAPTRADDR]], align 8
  // CHECK:      [[FNPTRADDR:%.*]] = getelementptr inbounds nuw [[BLOCK_T]], ptr [[BLOCK]], i32 0, i32 3
  // CHECK-NEXT: [[DISCRIMINATOR:%.*]] = ptrtoint ptr [[FNPTRADDR]] to i64
  // CHECK-NEXT: [[SIGNED:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr {{@.*}} to i64), i32 0, i64 [[DISCRIMINATOR]])
  // CHECK-NEXT: [[T0:%.*]] = inttoptr i64 [[SIGNED]] to ptr
  // CHECK-NEXT: store ptr [[T0]], ptr [[FNPTRADDR]]
  use_block(^{return i;});
}

// CHECK-LABEL: define void @test_copy_destroy
void test_copy_destroy(A *a) {
  // CHECK: [[COPYDISPOSE_DESCRIPTOR]]
  use_block(^{return [a count];});
}

// CHECK-LABEL: define void @test_byref_copy_destroy
void test_byref_copy_destroy(A *a) {
  // CHECK:      [[COPY_FIELD:%.*]] = getelementptr inbounds nuw [[BYREF_T:%.*]], ptr [[BYREF:%.*]], i32 0, i32 4
  // CHECK-NEXT: [[T0:%.*]] = ptrtoint ptr [[COPY_FIELD]] to i64
  // CHECK-NEXT: [[T1:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr {{@.*}} to i64), i32 0, i64 [[T0]])
  // CHECK-NEXT: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
  // CHECK-NEXT: store ptr [[T2]], ptr [[COPY_FIELD]], align 8
  // CHECK:      [[DISPOSE_FIELD:%.*]] = getelementptr inbounds nuw [[BYREF_T]], ptr [[BYREF]], i32 0, i32 5
  // CHECK-NEXT: [[T0:%.*]] = ptrtoint ptr [[DISPOSE_FIELD]] to i64
  // CHECK-NEXT: [[T1:%.*]] = call i64 @llvm.ptrauth.sign(i64 ptrtoint (ptr {{@.*}} to i64), i32 0, i64 [[T0]])
  // CHECK-NEXT: [[T2:%.*]] = inttoptr i64 [[T1]] to ptr
  // CHECK-NEXT: store ptr [[T2]], ptr [[DISPOSE_FIELD]], align 8
  __block A *aweak = a;
  use_block(^{return [aweak count];});
}

void test_conversion_helper(id);

void test_conversion(id a) {
  test_conversion_helper(^{
    (void)a;
  });
}
