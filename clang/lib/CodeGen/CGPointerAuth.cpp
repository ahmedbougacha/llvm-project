//===--- CGPointerAuth.cpp - IR generation for pointer authentication -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains common routines relating to the emission of
// pointer authentication operations.
//
//===----------------------------------------------------------------------===//

#include "CGCXXABI.h"
#include "CGCall.h"
#include "CodeGenFunction.h"
#include "CodeGenModule.h"
#include "clang/AST/Attr.h"
#include "clang/AST/StableHash.h"
#include "clang/Basic/PointerAuthOptions.h"
#include "clang/CodeGen/CodeGenABITypes.h"
#include "clang/CodeGen/ConstantInitBuilder.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Analysis/ValueTracking.h"
#include <vector>

using namespace clang;
using namespace CodeGen;

/// Given a pointer-authentication schema, return a concrete "other"
/// discriminator for it.
llvm::Constant *CodeGenModule::getPointerAuthOtherDiscriminator(
    const PointerAuthSchema &schema, GlobalDecl decl, QualType type) {
  switch (schema.getOtherDiscrimination()) {
  case PointerAuthSchema::Discrimination::None:
    return nullptr;

  case PointerAuthSchema::Discrimination::Type:
    assert(!type.isNull() && "type not provided for type-discriminated schema");
    return llvm::ConstantInt::get(
        IntPtrTy, getContext().getPointerAuthTypeDiscriminator(type));

  case PointerAuthSchema::Discrimination::Decl:
    assert(decl.getDecl() &&
           "declaration not provided for decl-discriminated schema");
    return llvm::ConstantInt::get(IntPtrTy,
                                  getPointerAuthDeclDiscriminator(decl));

  case PointerAuthSchema::Discrimination::Constant:
    return llvm::ConstantInt::get(IntPtrTy, schema.getConstantDiscrimination());
  }
  llvm_unreachable("bad discrimination kind");
}

uint16_t CodeGen::getPointerAuthTypeDiscriminator(CodeGenModule &CGM,
                                                  QualType functionType) {
  return CGM.getContext().getPointerAuthTypeDiscriminator(functionType);
}

/// Compute an ABI-stable hash of the given string.
uint64_t CodeGen::computeStableStringHash(StringRef string) {
  return clang::getStableStringHash(string);
}

uint16_t CodeGen::getPointerAuthDeclDiscriminator(CodeGenModule &CGM,
                                                  GlobalDecl declaration) {
  return CGM.getPointerAuthDeclDiscriminator(declaration);
}

/// Return the "other" decl-specific discriminator for the given decl.
uint16_t
CodeGenModule::getPointerAuthDeclDiscriminator(GlobalDecl declaration) {
  uint16_t &entityHash = PtrAuthDiscriminatorHashes[declaration];

  if (entityHash == 0) {
    StringRef name = getMangledName(declaration);
    entityHash = getPointerAuthStringDiscriminator(getContext(), name);
  }

  return entityHash;
}

/// Return the abstract pointer authentication schema for a pointer to the given
/// function type.
CGPointerAuthInfo CodeGenModule::getFunctionPointerAuthInfo(QualType T) {
  auto &Schema = getCodeGenOpts().PointerAuth.FunctionPointers;
  if (!Schema)
    return CGPointerAuthInfo();

  assert(!Schema.isAddressDiscriminated() &&
         "function pointers cannot use address-specific discrimination");

  llvm::Constant *Discriminator = nullptr;
  if (T->isFunctionPointerType() || T->isFunctionReferenceType())
    T = T->getPointeeType();
  if (T->isFunctionType())
    Discriminator = getPointerAuthOtherDiscriminator(Schema, GlobalDecl(), T);

  return CGPointerAuthInfo(Schema.getKey(), Schema.getAuthenticationMode(),
                           Discriminator);
}

/// Return the natural pointer authentication for values of the given
/// pointee type.
static CGPointerAuthInfo
getPointerAuthInfoForPointeeType(CodeGenModule &CGM, QualType pointeeType) {
  if (pointeeType.isNull())
    return CGPointerAuthInfo();

  // Function pointers use the function-pointer schema by default.
  if (pointeeType->isFunctionType())
    return CGM.getFunctionPointerAuthInfo(pointeeType);

  // Normal data pointers never use direct pointer authentication by default.
  return CGPointerAuthInfo();
}

CGPointerAuthInfo
CodeGenModule::getPointerAuthInfoForPointeeType(QualType type) {
  return ::getPointerAuthInfoForPointeeType(*this, type);
}

/// Return the natural pointer authentication for values of the given
/// pointer type.
static CGPointerAuthInfo getPointerAuthInfoForType(CodeGenModule &CGM,
                                                   QualType pointerType) {
  assert(pointerType->isSignableValue(CGM.getContext()));

  // Block pointers are currently not signed.
  if (pointerType->isBlockPointerType())
    return CGPointerAuthInfo();

  auto pointeeType = pointerType->getPointeeType();

  if (pointeeType.isNull())
    return CGPointerAuthInfo();

  return ::getPointerAuthInfoForPointeeType(CGM, pointeeType);
}

CGPointerAuthInfo CodeGenModule::getPointerAuthInfoForType(QualType type) {
  return ::getPointerAuthInfoForType(*this, type);
}

llvm::Value *
CodeGenFunction::EmitPointerAuthBlendDiscriminator(llvm::Value *storageAddress,
                                                   llvm::Value *discriminator) {
  storageAddress = Builder.CreatePtrToInt(storageAddress, IntPtrTy);
  auto intrinsic = CGM.getIntrinsic(llvm::Intrinsic::ptrauth_blend);
  return Builder.CreateCall(intrinsic, {storageAddress, discriminator});
}

/// Emit the concrete pointer authentication informaton for the
/// given authentication schema.
CGPointerAuthInfo CodeGenFunction::EmitPointerAuthInfo(
    const PointerAuthSchema &schema, llvm::Value *storageAddress,
    GlobalDecl schemaDecl, QualType schemaType) {
  if (!schema)
    return CGPointerAuthInfo();

  llvm::Value *discriminator =
      CGM.getPointerAuthOtherDiscriminator(schema, schemaDecl, schemaType);

  if (schema.isAddressDiscriminated()) {
    assert(storageAddress &&
           "address not provided for address-discriminated schema");

    if (discriminator)
      discriminator =
          EmitPointerAuthBlendDiscriminator(storageAddress, discriminator);
    else
      discriminator = Builder.CreatePtrToInt(storageAddress, IntPtrTy);
  }

  return CGPointerAuthInfo(schema.getKey(), schema.getAuthenticationMode(),
                           discriminator);
}

Address CodeGenFunction::mergeAddressesInConditionalExpr(
    Address LHS, Address RHS, llvm::BasicBlock *LHSBlock,
    llvm::BasicBlock *RHSBlock, llvm::BasicBlock *MergeBlock,
    QualType MergedType) {
  CGPointerAuthInfo LHSInfo = LHS.getPointerAuthInfo();
  CGPointerAuthInfo RHSInfo = RHS.getPointerAuthInfo();

  if (LHSInfo || RHSInfo) {
    if (LHSInfo != RHSInfo || LHS.getOffset() != RHS.getOffset() ||
        LHS.getBasePointer()->getType() != RHS.getBasePointer()->getType()) {
      // If the LHS and RHS have different signing information, offsets, or base
      // pointer types, resign both sides and clear out the offsets.
      CGPointerAuthInfo NewInfo =
          CGM.getPointerAuthInfoForPointeeType(MergedType);
      LHSBlock->getTerminator()->eraseFromParent();
      Builder.SetInsertPoint(LHSBlock);
      LHS = LHS.getResignedAddress(NewInfo, *this);
      Builder.CreateBr(MergeBlock);
      LHSBlock = Builder.GetInsertBlock();
      RHSBlock->getTerminator()->eraseFromParent();
      Builder.SetInsertPoint(RHSBlock);
      RHS = RHS.getResignedAddress(NewInfo, *this);
      Builder.CreateBr(MergeBlock);
      RHSBlock = Builder.GetInsertBlock();
    }

    assert(LHS.getPointerAuthInfo() == RHS.getPointerAuthInfo() &&
           LHS.getOffset() == RHS.getOffset() &&
           LHS.getBasePointer()->getType() == RHS.getBasePointer()->getType() &&
           "lhs and rhs must have the same signing information, offsets, and "
           "base pointer types");
  }

  Builder.SetInsertPoint(MergeBlock);
  llvm::PHINode *PtrPhi = Builder.CreatePHI(LHS.getType(), 2, "cond");
  PtrPhi->addIncoming(LHS.getBasePointer(), LHSBlock);
  PtrPhi->addIncoming(RHS.getBasePointer(), RHSBlock);
  LHS.replaceBasePointer(PtrPhi);
  LHS.setAlignment(std::min(LHS.getAlignment(), RHS.getAlignment()));
  return LHS;
}

static bool isZeroConstant(llvm::Value *value) {
  if (auto ci = dyn_cast<llvm::ConstantInt>(value))
    return ci->isZero();
  return false;
}

static bool equalAuthPolicies(const CGPointerAuthInfo &left,
                              const CGPointerAuthInfo &right) {
  if (left.isSigned() != right.isSigned())
    return false;
  assert(left.isSigned() && right.isSigned() &&
         "should only be called with non-null auth policies");
  return left.getKey() == right.getKey() &&
         left.getAuthenticationMode() == right.getAuthenticationMode();
}

llvm::Value *CodeGenFunction::EmitPointerAuthResign(
    llvm::Value *value, QualType type, const CGPointerAuthInfo &curAuthInfo,
    const CGPointerAuthInfo &newAuthInfo, bool isKnownNonNull) {
  // Fast path: if neither schema wants a signature, we're done.
  if (!curAuthInfo && !newAuthInfo)
    return value;

  llvm::Value *null = nullptr;
  // If the value is obviously null, we're done.
  if (auto pointerValue = dyn_cast<llvm::PointerType>(value->getType())) {
    null = CGM.getNullPointer(pointerValue, type);
  } else {
    assert(value->getType()->isIntegerTy());
    null = llvm::ConstantInt::get(IntPtrTy, 0);
  }
  if (value == null) {
    return value;
  }

  // If both schemas sign the same way, we're done.
  if (equalAuthPolicies(curAuthInfo, newAuthInfo)) {
    auto curD = curAuthInfo.getDiscriminator();
    auto newD = newAuthInfo.getDiscriminator();
    if (curD == newD)
      return value;

    if ((curD == nullptr && isZeroConstant(newD)) ||
        (newD == nullptr && isZeroConstant(curD)))
      return value;
  }

  llvm::BasicBlock *initBB = Builder.GetInsertBlock();
  llvm::BasicBlock *resignBB = nullptr, *contBB = nullptr;

  // Null pointers have to be mapped to null, and the ptrauth_resign
  // intrinsic doesn't do that.
  if (!isKnownNonNull && !llvm::isKnownNonZero(value, CGM.getDataLayout())) {
    contBB = createBasicBlock("resign.cont");
    resignBB = createBasicBlock("resign.nonnull");

    auto isNonNull = Builder.CreateICmpNE(value, null);
    Builder.CreateCondBr(isNonNull, resignBB, contBB);
    EmitBlock(resignBB);
  }

  // Perform the auth/sign/resign operation.
  if (!newAuthInfo) {
    value = EmitPointerAuthAuth(curAuthInfo, value);
  } else if (!curAuthInfo) {
    value = EmitPointerAuthSign(newAuthInfo, value);
  } else {
    value = EmitPointerAuthResignCall(value, curAuthInfo, newAuthInfo);
  }

  // Clean up with a phi if we branched before.
  if (contBB) {
    EmitBlock(contBB);
    auto phi = Builder.CreatePHI(value->getType(), 2);
    phi->addIncoming(null, initBB);
    phi->addIncoming(value, resignBB);
    value = phi;
  }

  return value;
}

/// Build a signed-pointer "ptrauth" constant.
static llvm::ConstantPtrAuth *
buildConstantAddress(CodeGenModule &CGM, llvm::Constant *pointer, unsigned key,
                     llvm::Constant *storageAddress,
                     llvm::Constant *otherDiscriminator) {
  llvm::Constant *addressDiscriminator = nullptr;
  if (storageAddress) {
    addressDiscriminator = storageAddress;
    assert(storageAddress->getType() == CGM.UnqualPtrTy);
  } else {
    addressDiscriminator = llvm::Constant::getNullValue(CGM.UnqualPtrTy);
  }

  llvm::ConstantInt *integerDiscriminator = nullptr;
  if (otherDiscriminator) {
    assert(otherDiscriminator->getType() == CGM.Int64Ty);
    integerDiscriminator = cast<llvm::ConstantInt>(otherDiscriminator);
  } else {
    integerDiscriminator = llvm::ConstantInt::get(CGM.Int64Ty, 0);
  }

  return llvm::ConstantPtrAuth::get(
    pointer, llvm::ConstantInt::get(CGM.Int32Ty, key), addressDiscriminator,
    integerDiscriminator);
}

llvm::Constant *
CodeGenModule::getConstantSignedPointer(llvm::Constant *pointer,
                                        unsigned key,
                                        llvm::Constant *storageAddress,
                                        llvm::Constant *otherDiscriminator) {
  // Unique based on the underlying value, not a signing of it.
  auto stripped = pointer->stripPointerCasts();

  // Build the constant.
  return buildConstantAddress(*this, stripped, key, storageAddress,
                              otherDiscriminator);
}

/// Does a given PointerAuthScheme require us to sign a value
static bool shouldSignPointer(const PointerAuthSchema &schema) {
  auto authenticationMode = schema.getAuthenticationMode();
  return authenticationMode == PointerAuthenticationMode::SignAndStrip ||
         authenticationMode == PointerAuthenticationMode::SignAndAuth;
}

/// Sign a constant pointer using the given scheme, producing a constant
/// with the same IR type.
llvm::Constant *CodeGenModule::getConstantSignedPointer(
    llvm::Constant *pointer, const PointerAuthSchema &schema,
    llvm::Constant *storageAddress, GlobalDecl schemaDecl,
    QualType schemaType) {
  assert(shouldSignPointer(schema));
  llvm::Constant *otherDiscriminator =
      getPointerAuthOtherDiscriminator(schema, schemaDecl, schemaType);

  return getConstantSignedPointer(pointer, schema.getKey(), storageAddress,
                                  otherDiscriminator);
}

llvm::Constant *
CodeGen::getConstantSignedPointer(CodeGenModule &CGM,
                                  llvm::Constant *pointer, unsigned key,
                                  llvm::Constant *storageAddress,
                                  llvm::Constant *otherDiscriminator) {
  return CGM.getConstantSignedPointer(pointer, key, storageAddress,
                                      otherDiscriminator);
}

llvm::Constant *CodeGenModule::getConstantSignedPointer(llvm::Constant *Pointer,
                                                        QualType PointeeType) {
  CGPointerAuthInfo Info = getPointerAuthInfoForPointeeType(PointeeType);
  if (!Info.shouldSign())
    return Pointer;
  return getConstantSignedPointer(
      Pointer, Info.getKey(), nullptr,
      cast<llvm::Constant>(Info.getDiscriminator()));
}

/// Sign the given pointer and add it to the constant initializer
/// currently being built.
void ConstantAggregateBuilderBase::addSignedPointer(
    llvm::Constant *pointer, const PointerAuthSchema &schema,
    GlobalDecl calleeDecl, QualType calleeType) {
  if (!schema || !shouldSignPointer(schema))
    return add(pointer);

  llvm::Constant *storageAddress = nullptr;
  if (schema.isAddressDiscriminated()) {
    storageAddress = getAddrOfCurrentPosition(pointer->getType());
  }

  llvm::Constant *signedPointer = Builder.CGM.getConstantSignedPointer(
      pointer, schema, storageAddress, calleeDecl, calleeType);
  add(signedPointer);
}

void ConstantAggregateBuilderBase::addSignedPointer(
    llvm::Constant *pointer, unsigned key, bool useAddressDiscrimination,
    llvm::Constant *otherDiscriminator) {
  llvm::Constant *storageAddress = nullptr;
  if (useAddressDiscrimination) {
    storageAddress = getAddrOfCurrentPosition(pointer->getType());
  }

  llvm::Constant *signedPointer = Builder.CGM.getConstantSignedPointer(
      pointer, key, storageAddress, otherDiscriminator);
  add(signedPointer);
}

/// If applicable, sign a given constant function pointer with the ABI rules for
/// functionType.
llvm::Constant *CodeGenModule::getFunctionPointer(llvm::Constant *pointer,
                                                  QualType functionType,
                                                  GlobalDecl GD) {
  assert(functionType->isFunctionType() ||
         functionType->isFunctionReferenceType() ||
         functionType->isFunctionPointerType());

  if (auto pointerAuth = getFunctionPointerAuthInfo(functionType)) {
    return getConstantSignedPointer(
      pointer, pointerAuth.getKey(), nullptr,
      cast_or_null<llvm::Constant>(pointerAuth.getDiscriminator()));
  }

  return pointer;
}

llvm::Constant *CodeGenModule::getFunctionPointer(GlobalDecl GD,
                                                  llvm::Type *Ty) {
  const FunctionDecl *FD = cast<FunctionDecl>(GD.getDecl());

  // Annoyingly, K&R functions have prototypes in the clang AST, but
  // expressions referring to them are unprototyped.
  QualType FuncType = FD->getType();
  if (!FD->hasPrototype())
    if (const auto *Proto = FuncType->getAs<FunctionProtoType>())
      FuncType = Context.getFunctionNoProtoType(Proto->getReturnType(),
                                                Proto->getExtInfo());

  return getFunctionPointer(getRawFunctionPointer(GD, Ty), FuncType, GD);
}

llvm::Value *CodeGenFunction::AuthPointerToPointerCast(llvm::Value *ResultPtr,
                                                       QualType SourceType,
                                                       QualType DestType) {
  CGPointerAuthInfo CurAuthInfo, NewAuthInfo;
  if (SourceType->isSignableValue(CGM.getContext()))
    CurAuthInfo = getPointerAuthInfoForType(CGM, SourceType);

  if (DestType->isSignableValue(CGM.getContext()))
    NewAuthInfo = getPointerAuthInfoForType(CGM, DestType);

  if (!CurAuthInfo && !NewAuthInfo)
    return ResultPtr;

  // If only one side of the cast is a function pointer, then we still need to
  // resign to handle casts to/from opaque pointers.
  if (!CurAuthInfo && DestType->isFunctionPointerType())
    CurAuthInfo = CGM.getFunctionPointerAuthInfo(SourceType);

  if (!NewAuthInfo && SourceType->isFunctionPointerType())
    NewAuthInfo = CGM.getFunctionPointerAuthInfo(DestType);

  return EmitPointerAuthResign(ResultPtr, DestType, CurAuthInfo, NewAuthInfo,
                               /*IsKnownNonNull=*/false);
}

Address CodeGenFunction::AuthPointerToPointerCast(Address Ptr,
                                                  QualType SourceType,
                                                  QualType DestType) {
  CGPointerAuthInfo CurAuthInfo, NewAuthInfo;
  if (SourceType->isSignableValue(CGM.getContext()))
    CurAuthInfo = getPointerAuthInfoForType(CGM, SourceType);

  if (DestType->isSignableValue(CGM.getContext()))
    NewAuthInfo = getPointerAuthInfoForType(CGM, DestType);

  if (!CurAuthInfo && !NewAuthInfo)
    return Ptr;

  if (!CurAuthInfo && DestType->isFunctionPointerType()) {
    // When casting a non-signed pointer to a function pointer, just set the
    // auth info on Ptr to the assumed schema. The pointer will be resigned to
    // the effective type when used.
    Ptr.setPointerAuthInfo(CGM.getFunctionPointerAuthInfo(SourceType));
    return Ptr;
  }

  if (!NewAuthInfo && SourceType->isFunctionPointerType()) {
    NewAuthInfo = CGM.getFunctionPointerAuthInfo(DestType);
    Ptr = Ptr.getResignedAddress(NewAuthInfo, *this);
    Ptr.setPointerAuthInfo(CGPointerAuthInfo());
    return Ptr;
  }

  return Ptr;
}

Address CodeGenFunction::EmitPointerAuthSign(Address Addr,
                                             QualType PointeeType) {
  CGPointerAuthInfo Info = getPointerAuthInfoForPointeeType(CGM, PointeeType);
  llvm::Value *Ptr = EmitPointerAuthSign(Info, Addr.emitRawPointer(*this));
  return Address(Ptr, Addr.getElementType(), Addr.getAlignment());
}

Address CodeGenFunction::EmitPointerAuthAuth(Address Addr,
                                             QualType PointeeType) {
  CGPointerAuthInfo Info = getPointerAuthInfoForPointeeType(CGM, PointeeType);
  llvm::Value *Ptr = EmitPointerAuthAuth(Info, Addr.emitRawPointer(*this));
  return Address(Ptr, Addr.getElementType(), Addr.getAlignment());
}

Address CodeGenFunction::getAsNaturalAddressOf(Address Addr,
                                               QualType PointeeTy) {
  CGPointerAuthInfo Info =
      PointeeTy.isNull() ? CGPointerAuthInfo()
                         : CGM.getPointerAuthInfoForPointeeType(PointeeTy);
  return Addr.getResignedAddress(Info, *this);
}

Address Address::getResignedAddress(const CGPointerAuthInfo &NewInfo,
                                    CodeGenFunction &CGF) const {
  assert(isValid() && "pointer isn't valid");
  CGPointerAuthInfo CurInfo = getPointerAuthInfo();
  llvm::Value *Val;

  // Nothing to do if neither the current or the new ptrauth info needs signing.
  if (!CurInfo.isSigned() && !NewInfo.isSigned())
    return Address(getUnsignedPointer(), getElementType(), getAlignment(),
                   isKnownNonNull());

  assert(ElementType && "Effective type has to be set");

  // If the current and the new ptrauth infos are the same and the offset is
  // null, just cast the base pointer to the effective type.
  if (CurInfo == NewInfo && !hasOffset())
    Val = getBasePointer();
  else {
    if (Offset) {
      assert(isSigned() && "signed pointer expected");
      // Authenticate the base pointer.
      Val = CGF.EmitPointerAuthResign(getBasePointer(), QualType(), CurInfo,
                                      CGPointerAuthInfo(), isKnownNonNull());

      // Add offset to the authenticated pointer.
      unsigned AS = cast<llvm::PointerType>(getBasePointer()->getType())
                        ->getAddressSpace();
      Val = CGF.Builder.CreateBitCast(Val,
                                      llvm::PointerType::get(CGF.Int8Ty, AS));
      Val = CGF.Builder.CreateGEP(CGF.Int8Ty, Val, Offset, "resignedgep");

      // Sign the pointer using the new ptrauth info.
      Val = CGF.EmitPointerAuthResign(Val, QualType(), CGPointerAuthInfo(),
                                      NewInfo, isKnownNonNull());
    } else {
      Val = CGF.EmitPointerAuthResign(getBasePointer(), QualType(), CurInfo,
                                      NewInfo, isKnownNonNull());
    }
  }

  Val = CGF.Builder.CreateBitCast(Val, getType());
  return Address(Val, getElementType(), getAlignment(), NewInfo, nullptr,
                 isKnownNonNull());
}

void Address::addOffset(CharUnits V, llvm::Type *Ty, CGBuilderTy &Builder) {
  assert(isSigned() &&
         "shouldn't add an offset if the base pointer isn't signed");
  Alignment = Alignment.alignmentAtOffset(V);
  llvm::Value *FixedOffset =
      llvm::ConstantInt::get(Builder.getCGF()->IntPtrTy, V.getQuantity());
  addOffset(FixedOffset, Ty, Builder, Alignment);
}

void Address::addOffset(llvm::Value *V, llvm::Type *Ty, CGBuilderTy &Builder,
                        CharUnits NewAlignment) {
  assert(isSigned() &&
         "shouldn't add an offset if the base pointer isn't signed");
  ElementType = Ty;
  Alignment = NewAlignment;

  if (!Offset) {
    Offset = V;
    return;
  }

  Offset = Builder.CreateAdd(Offset, V, "add");
}

llvm::Value *Address::emitRawPointerSlow(CodeGenFunction &CGF) const {
  return CGF.getAsNaturalPointerTo(*this, QualType());
}

llvm::Value *RValue::getAggregatePointer(QualType PointeeType,
                                         CodeGenFunction &CGF) const {
  return CGF.getAsNaturalPointerTo(getAggregateAddress(), PointeeType);
}

llvm::Value *LValue::getPointer(CodeGenFunction &CGF) const {
  assert(isSimple());
  return emitResignedPointer(getType(), CGF);
}

llvm::Value *LValue::emitResignedPointer(QualType PointeeTy,
                                         CodeGenFunction &CGF) const {
  assert(isSimple());
  return CGF.getAsNaturalAddressOf(Addr, PointeeTy).getBasePointer();
}

llvm::Value *LValue::emitRawPointer(CodeGenFunction &CGF) const {
  assert(isSimple());
  return Addr.isValid() ? Addr.emitRawPointer(CGF) : nullptr;
}

llvm::Value *AggValueSlot::getPointer(QualType PointeeTy,
                                      CodeGenFunction &CGF) const {
  Address SignedAddr = CGF.getAsNaturalAddressOf(Addr, PointeeTy);
  return SignedAddr.getBasePointer();
}

llvm::Value *AggValueSlot::emitRawPointer(CodeGenFunction &CGF) const {
  return Addr.isValid() ? Addr.emitRawPointer(CGF) : nullptr;
}
