; RUN: llvm-as < %s | llvm-dis | FileCheck %s

@var = global i32 0

; CHECK: @basic = global ptr ptrauth (ptr @var, i32 0, ptr null, i64 0)
@basic = global ptr ptrauth (ptr @var, i32 0, ptr null, i64 0)

; CHECK: @keyed = global ptr ptrauth (ptr @var, i32 3, ptr null, i64 0)
@keyed = global ptr ptrauth (ptr @var, i32 3, ptr null, i64 0)

; CHECK: @intdisc = global ptr ptrauth (ptr @var, i32 0, ptr null, i64 -1)
@intdisc = global ptr ptrauth (ptr @var, i32 0, ptr null, i64 -1)

@addrdisc_storage = global ptr null
; CHECK: @addrdisc = global ptr ptrauth (ptr @var, i32 2, ptr @addrdisc_storage, i64 1234)
@addrdisc = global ptr ptrauth (ptr @var, i32 2, ptr @addrdisc_storage, i64 1234)


@var1 = addrspace(1) global i32 0

; CHECK: @addrspace = global ptr addrspace(1) ptrauth (ptr addrspace(1) @var1, i32 0, ptr null, i64 0)
@addrspace = global ptr addrspace(1) ptrauth (ptr addrspace(1) @var1, i32 0, ptr null, i64 0)

@addrspace_addrdisc_storage = addrspace(2) global ptr addrspace(1) null
; CHECK: @addrspace_addrdisc = global ptr addrspace(1) ptrauth (ptr addrspace(1) @var1, i32 2, ptr addrspace(2) @addrspace_addrdisc_storage, i64 1234)
@addrspace_addrdisc = global ptr addrspace(1) ptrauth (ptr addrspace(1) @var1, i32 2, ptr addrspace(2) @addrspace_addrdisc_storage, i64 1234)
