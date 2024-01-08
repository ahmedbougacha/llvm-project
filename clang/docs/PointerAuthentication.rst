Pointer Authentication
======================

.. contents::
   :local:

Introduction
------------

Pointer authentication is a technology which offers strong probabilistic
protection against exploiting a broad class of memory bugs to take control of
program execution.  When adopted consistently in a language ABI, it provides
a form of relatively fine-grained control flow integrity (CFI) check that
resists both return-oriented programming (ROP) and jump-oriented programming
(JOP) attacks.

While pointer authentication can be implemented purely in software, direct
hardware support (e.g. as provided by Armv8.3 PAuth) can dramatically improve
performance and code size.  Similarly, while pointer authentication
can be implemented on any architecture, taking advantage of the (typically)
excess addressing range of a target with 64-bit pointers minimizes the impact
on memory performance and can allow interoperation with existing code (by
disabling pointer authentication dynamically).  This document will generally
attempt to present the pointer authentication feature independent of any
hardware implementation or ABI.  Considerations that are
implementation-specific are clearly identified throughout.

Note that there are several different terms in use:

- **Pointer authentication** is a target-independent language technology.

- **PAuth** (sometimes referred to as **PAC**, for Pointer Authentication
  Codes) is an AArch64 architecture extension that provides hardware support
  for pointer authentication.  Additional extensions either modify some of the
  PAuth instruction behavior (notably FPAC), or provide new instruction
  variants (PAuth_LR).

- **Armv8.3** is an AArch64 architecture revision that makes PAuth mandatory.

- **arm64e** is a specific ABI (not yet fully stable) for implementing pointer
  authentication using PAuth on certain Apple operating systems.

This document serves four purposes:

- It describes the basic ideas of pointer authentication.

- It documents several language extensions that are useful on targets using
  pointer authentication.

- It presents a theory of operation for the security mitigation, describing the
  basic requirements for correctness, various weaknesses in the mechanism, and
  ways in which programmers can strengthen its protections (including
  recommendations for language implementors).

- It will eventually document the language ABIs currently used for C, C++,
  Objective-C, and Swift on arm64e, although these are not yet stable on any
  target.

Basic Concepts
--------------

The simple address of an object or function is a **raw pointer**.  A raw
pointer can be **signed** to produce a **signed pointer**.  A signed pointer
can be then **authenticated** in order to verify that it was **validly signed**
and extract the original raw pointer.  These terms reflect the most likely
implementation technique: computing and storing a cryptographic signature along
with the pointer.

An **abstract signing key** is a name which refers to a secret key which is
used to sign and authenticate pointers.  The concrete key value for a
particular name is consistent throughout a process.

A **discriminator** is an arbitrary value used to **diversify** signed pointers
so that one validly-signed pointer cannot simply be copied over another.
A discriminator is simply opaque data of some implementation-defined size that
is included in the signature as a salt (see `Discriminators`_ for details.)

Nearly all aspects of pointer authentication use just these two primary
operations:

- ``sign(raw_pointer, key, discriminator)`` produces a signed pointer given
  a raw pointer, an abstract signing key, and a discriminator.

- ``auth(signed_pointer, key, discriminator)`` produces a raw pointer given
  a signed pointer, an abstract signing key, and a discriminator.

``auth(sign(raw_pointer, key, discriminator), key, discriminator)`` must
succeed and produce ``raw_pointer``.  ``auth`` applied to a value that was
ultimately produced in any other way is expected to fail, which halts the
program either:

- immediately, on implementations that enforce ``auth`` success (e.g., when
  using compiler-generated ``auth`` failure checks, or Armv8.3 with the FPAC
  extension), or

- when the resulting pointer value is used, on implementations that don't.

However, regardless of the implementation's handling of ``auth`` failures, it
is permitted for ``auth`` to fail to detect that a signed pointer was not
produced in this way, in which case it may return anything; this is what makes
pointer authentication a probabilistic mitigation rather than a perfect one.

There are two secondary operations which are required only to implement certain
intrinsics in ``<ptrauth.h>``:

- ``strip(signed_pointer, key)`` produces a raw pointer given a signed pointer
  and a key without verifying its validity, unlike ``auth``.  This is useful
  for certain kinds of tooling, such as crash backtraces; it should generally
  not be used in the basic language ABI except in very careful ways.

- ``sign_generic(value)`` produces a cryptographic signature for arbitrary
  data, not necessarily a pointer.  This is useful for efficiently verifying
  that non-pointer data has not been tampered with.

Whenever any of these operations is called for, the key value must be known
statically.  This is because the layout of a signed pointer may vary according
to the signing key.  (For example, in Armv8.3, the layout of a signed pointer
depends on whether Top Byte Ignore (TBI) is enabled, which can be set
independently for I and D keys.)

.. admonition:: Note for API designers and language implementors

  These are the *primitive* operations of pointer authentication, provided for
  clarity of description.  They are not suitable either as high-level
  interfaces or as primitives in a compiler IR because they expose raw
  pointers.  Raw pointers require special attention in the language
  implementation to avoid the accidental creation of exploitable code
  sequences; see the section on `Attackable code sequences`_.

The following details are all implementation-defined:

- the nature of a signed pointer
- the size of a discriminator
- the number and nature of the signing keys
- the implementation of the ``sign``, ``auth``, ``strip``, and ``sign_generic``
  operations

While the use of the terms "sign" and "signed pointer" suggest the use of
a cryptographic signature, other implementations may be possible.  See
`Alternative implementations`_ for an exploration of implementation options.

.. admonition:: Implementation example: Armv8.3

  Readers may find it helpful to know how these terms map to Armv8.3 PAuth:

  - A signed pointer is a pointer with a signature stored in the
    otherwise-unused high bits.  The kernel configures the address width based
    on the system's addressing needs, and enables TBI for I or D keys as
    needed.  The bits above the address bits and below the TBI bits (if
    enabled) are unused.  The signature width then depends on this addressing
    configuration.

  - A discriminator is a 64-bit integer.  Constant discriminators are 16-bit
    integers.  Blending a constant discriminator into an address consists of
    replacing the top 16 bits of the pointer containing the address with the
    constant.  Pointers used for blending purposes should only have address
    bits, since higher bits will be at least partially overwritten with the
    constant discriminator.

  - There are five 128-bit signing-key registers, each of which can only be
    directly read or set by privileged code.  Of these, four are used for
    signing pointers, and the fifth is used only for ``sign_generic``.  The key
    data is simply a pepper added to the hash, not an encryption key, and so
    can be initialized using random data.

  - ``sign`` computes a cryptographic hash of the pointer, discriminator, and
    signing key, and stores it in the high bits as the signature. ``auth``
    removes the signature, computes the same hash, and compares the result with
    the stored signature.  ``strip`` removes the signature without
    authenticating it.  While ``aut*`` instructions do not themselves trap on
    failure in Armv8.3 PAuth, they do with the later optional FPAC extension.
    An implementation can also choose to emulate this trapping behavior by
    emitting additional instructions around ``aut*``.

  - ``sign_generic`` corresponds to the ``pacga`` instruction, which takes two
    64-bit values and produces a 64-bit cryptographic hash. Implementations of
    this instruction are not required to produce meaningful data in all bits of
    the result.

Discriminators
~~~~~~~~~~~~~~

A discriminator is arbitrary extra data which alters the signature calculated
for a pointer.  When two pointers are signed differently --- either with
different keys or with different discriminators --- an attacker cannot simply
replace one pointer with the other.  For more information on why discriminators
are important and how to use them effectively, see the section on `Substitution
attacks`_.

To use standard cryptographic terminology, a discriminator acts as a
`salt <https://en.wikipedia.org/wiki/Salt_(cryptography)>`_ in the signing of a
pointer, and the key data acts as a
`pepper <https://en.wikipedia.org/wiki/Pepper_(cryptography)>`_.  That is,
both the discriminator and key data are ultimately just added as inputs to the
signing algorithm along with the pointer, but they serve significantly
different roles.  The key data is a common secret added to every signature,
whereas the discriminator is a value that can be derived from
the context in which a specific pointer is signed.  However, unlike a password
salt, it's important that discriminators be *independently* derived from the
circumstances of the signing; they should never simply be stored alongside
a pointer.  Discriminators are then re-derived in authentication operations.

The intrinsic interface in ``<ptrauth.h>`` allows an arbitrary discriminator
value to be provided, but can only be used when running normal code.  The
discriminators used by language ABIs must be restricted to make it feasible for
the loader to sign pointers stored in global memory without needing excessive
amounts of metadata.  Under these restrictions, a discriminator may consist of
either or both of the following:

- The address at which the pointer is stored in memory.  A pointer signed with
  a discriminator which incorporates its storage address is said to have
  **address diversity**.  In general, using address diversity means that
  a pointer cannot be reliably copied by an attacker to or from a different
  memory location.  However, an attacker may still be able to attack a larger
  call sequence if they can alter the address through which the pointer is
  accessed.  Furthermore, some situations cannot use address diversity because
  of language or other restrictions.

- A constant integer, called a **constant discriminator**. A pointer signed
  with a non-zero constant discriminator is said to have **constant
  diversity**.  If the discriminator is specific to a single declaration, it is
  said to have **declaration diversity**; if the discriminator is specific to
  a type of value, it is said to have **type diversity**.  For example, C++
  v-tables on arm64e sign their component functions using a hash of their
  method names and signatures, which provides declaration diversity; similarly,
  C++ member function pointers sign their invocation functions using a hash of
  the member pointer type, which provides type diversity.

The implementation may need to restrict constant discriminators to be
significantly smaller than the full size of a discriminator.  For example, on
arm64e, constant discriminators are only 16-bit values.  This is believed to
not significantly weaken the mitigation, since collisions remain uncommon.

The algorithm for blending a constant discriminator with a storage address is
implementation-defined.

.. _Signing schemas:

Signing Schemas
~~~~~~~~~~~~~~~

Correct use of pointer authentication requires the signing code and the
authenticating code to agree about the **signing schema** for the pointer:

- the abstract signing key with which the pointer should be signed and
- an algorithm for computing the discriminator.

As described in the section above on `Discriminators`_, in most situations, the
discriminator is produced by taking a constant discriminator and optionally
blending it with the storage address of the pointer.  In these situations, the
signing schema breaks down even more simply:

- the abstract signing key,
- a constant discriminator, and
- whether to use address diversity.

It is important that the signing schema be independently derived at all signing
and authentication sites.  Preferably, the schema should be hard-coded
everywhere it is needed, but at the very least, it must not be derived by
inspecting information stored along with the pointer.  See the section on
`Attacks on pointer authentication`_ for more information.

Language Features
-----------------

There is currently one main pointer authentication language feature:

- The language provides the ``<ptrauth.h>`` intrinsic interface for manually
  signing and authenticating pointers in code.  These can be used in
  circumstances where very specific behavior is required.


Language Extensions
~~~~~~~~~~~~~~~~~~~

Feature Testing
^^^^^^^^^^^^^^^

Whether the current target uses pointer authentication can be tested for with
a number of different tests.

- ``__has_feature(ptrauth_intrinsics)`` is true if ``<ptrauth.h>`` provides its
  normal interface.  This may be true even on targets where pointer
  authentication is not enabled by default.

__ptrauth Qualifier
^^^^^^^^^^^^^^^^^^^

``__ptrauth(key, address, discriminator)`` is an extended type
qualifier which causes so-qualified objects to hold pointers signed using the
specified schema rather than the default schema for such types.

In the current implementation in Clang, the qualified type must be a C pointer
type, either to a function or to an object.  It currently cannot be an
Objective-C pointer type, a C++ reference type, or a block pointer type; these
restrictions may be lifted in the future.

The qualifier's operands are as follows:

- ``key`` - an expression evaluating to a key value from ``<ptrauth.h>``; must
  be a constant expression

- ``address`` - whether to use address diversity (1) or not (0); must be
  a constant expression with one of these two values

- ``discriminator`` - a constant discriminator; must be a constant expression

See `Discriminators`_ for more information about discriminators.

Currently the operands must be constant-evaluable even within templates. In the
future this restriction may be lifted to allow value-dependent expressions as
long as they instantiate to a constant expression.

Consistent with the ordinary C/C++ rule for parameters, top-level ``__ptrauth``
qualifiers on a parameter (after parameter type adjustment) are ignored when
deriving the type of the function.  The parameter will be passed using the
default ABI for the unqualified pointer type.

If ``x`` is an object of type ``__ptrauth(key, address, discriminator) T``,
then the signing schema of the value stored in ``x`` is a key of ``key`` and
a discriminator determined as follows:

- if ``address`` is 0, then the discriminator is ``discriminator``;

- if ``address`` is 1 and ``discriminator`` is 0, then the discriminator is
  ``&x``; otherwise

- if ``address`` is 1 and ``discriminator`` is non-zero, then the discriminator
  is ``ptrauth_blend_discriminator(&x, discriminator)``; see
  `ptrauth_blend_discriminator`_.

``<ptrauth.h>``
~~~~~~~~~~~~~~~

This header defines the following types and operations:

``ptrauth_key``
^^^^^^^^^^^^^^^

This ``enum`` is the type of abstract signing keys.  In addition to defining
the set of implementation-specific signing keys (for example, Armv8.3 defines
``ptrauth_key_asia``), it also defines some portable aliases for those keys.
For example, ``ptrauth_key_function_pointer`` is the key generally used for
C function pointers, which will generally be suitable for other
function-signing schemas.

In all the operation descriptions below, key values must be constant values
corresponding to one of the implementation-specific abstract signing keys from
this ``enum``.

``ptrauth_extra_data_t``
^^^^^^^^^^^^^^^^^^^^^^^^

This is a ``typedef`` of a standard integer type of the correct size to hold
a discriminator value.

In the signing and authentication operation descriptions below, discriminator
values must have either pointer type or integer type. If the discriminator is
an integer, it will be coerced to ``ptrauth_extra_data_t``.

``ptrauth_blend_discriminator``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_blend_discriminator(pointer, integer)

Produce a discriminator value which blends information from the given pointer
and the given integer.

Implementations may ignore some bits from each value, which is to say, the
blending algorithm may be chosen for speed and convenience over theoretical
strength as a hash-combining algorithm.  For example, arm64e simply overwrites
the high 16 bits of the pointer with the low 16 bits of the integer, which can
be done in a single instruction with an immediate integer.

``pointer`` must have pointer type, and ``integer`` must have integer type. The
result has type ``ptrauth_extra_data_t``.

``ptrauth_string_discriminator``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_string_discriminator(string)

Compute a constant discriminator from the given string.

``string`` must be a string literal of ``char`` character type.  The result has
type ``ptrauth_extra_data_t``.

The result value is never zero and always within range for both the
``__ptrauth`` qualifier and ``ptrauth_blend_discriminator``.

This can be used in constant expressions.

``ptrauth_strip``
^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_strip(signedPointer, key)

Given that ``signedPointer`` matches the layout for signed pointers signed with
the given key, extract the raw pointer from it.  This operation does not trap
and cannot fail, even if the pointer is not validly signed.

``ptrauth_sign_constant``
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_sign_constant(pointer, key, discriminator)

Return a signed pointer for a constant address in a manner which guarantees
a non-attackable sequence.

``pointer`` must be a constant expression of pointer type which evaluates to
a non-null pointer.
``key``  must be a constant expression of type ``ptrauth_key``.
``discriminator`` must be a constant expression of pointer or integer type;
if an integer, it will be coerced to ``ptrauth_extra_data_t``.
The result will have the same type as ``pointer``.

This can be used in constant expressions.

``ptrauth_sign_unauthenticated``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_sign_unauthenticated(pointer, key, discriminator)

Produce a signed pointer for the given raw pointer without applying any
authentication or extra treatment.  This operation is not required to have the
same behavior on a null pointer that the language implementation would.

This is a treacherous operation that can easily result in `signing oracles`_.
Programs should use it seldom and carefully.

``ptrauth_auth_and_resign``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_auth_and_resign(pointer, oldKey, oldDiscriminator, newKey, newDiscriminator)

Authenticate that ``pointer`` is signed with ``oldKey`` and
``oldDiscriminator`` and then resign the raw-pointer result of that
authentication with ``newKey`` and ``newDiscriminator``.

``pointer`` must have pointer type.  The result will have the same type as
``pointer``.  This operation is not required to have the same behavior on
a null pointer that the language implementation would.

The code sequence produced for this operation must not be directly attackable.
However, if the discriminator values are not constant integers, their
computations may still be attackable.  In the future, Clang should be enhanced
to guaranteed non-attackability if these expressions are
:ref:`safely-derived<Safe derivation>`.

``ptrauth_auth_data``
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_auth_data(pointer, key, discriminator)

Authenticate that ``pointer`` is signed with ``key`` and ``discriminator`` and
remove the signature.

``pointer`` must have object pointer type.  The result will have the same type
as ``pointer``.  This operation is not required to have the same behavior on
a null pointer that the language implementation would.

In the future when Clang makes `safe derivation`_ guarantees, the result of
this operation should be considered safely-derived.

``ptrauth_sign_generic_data``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

  ptrauth_sign_generic_data(value1, value2)

Computes a signature for the given pair of values, incorporating a secret
signing key.

This operation can be used to verify that arbitrary data has not been tampered
with by computing a signature for the data, storing that signature, and then
repeating this process and verifying that it yields the same result.  This can
be reasonably done in any number of ways; for example, a library could compute
an ordinary checksum of the data and just sign the result in order to get the
tamper-resistance advantages of the secret signing key (since otherwise an
attacker could reliably overwrite both the data and the checksum).

``value1`` and ``value2`` must be either pointers or integers.  If the integers
are larger than ``uintptr_t`` then data not representable in ``uintptr_t`` may
be discarded.

The result will have type ``ptrauth_generic_signature_t``, which is an integer
type.  Implementations are not required to make all bits of the result equally
significant; in particular, some implementations are known to not leave
meaningful data in the low bits.



Theory of Operation
-------------------

The threat model of pointer authentication is as follows:

- The attacker has the ability to read and write to a certain range of
  addresses, possibly the entire address space.  However, they are constrained
  by the normal rules of the process: for example, they cannot write to memory
  that is mapped read-only, and if they access unmapped memory it will trigger
  a trap.

- The attacker has no ability to add arbitrary executable code to the program.
  For example, the program does not include malicious code to begin with, and
  the attacker cannot alter existing instructions, load a malicious shared
  library, or remap writable pages as executable.  If the attacker wants to get
  the process to perform a specific sequence of actions, they must somehow
  subvert the normal control flow of the process.

In both of the above paragraphs, it is merely assumed that the attacker's
*current* capabilities are restricted; that is, their current exploit does not
directly give them the power to do these things.  The attacker's immediate goal
may well be to leverage their exploit to gain these capabilities, e.g. to load
a malicious dynamic library into the process, even though the process does not
directly contain code to do so.

Note that any bug that fits the above threat model can be immediately exploited
as a denial-of-service attack by simply performing an illegal access and
crashing the program.  Pointer authentication cannot protect against this.
While denial-of-service attacks are unfortunate, they are also unquestionably
the best possible result of a bug this severe. Therefore, pointer
authentication enthusiastically embraces the idea of halting the program on
a pointer authentication failure rather than continuing in a possibly
compromised state.

Pointer authentication is a form of control-flow integrity (CFI) enforcement.
The basic security hypothesis behind CFI enforcement is that many bugs can only
be usefully exploited (other than as a denial-of-service) by leveraging them to
subvert the control flow of the program.  If this is true, then by inhibiting
or limiting that subversion, it may be possible to largely mitigate the
security consequences of those bugs by rendering them impractical (or, ideally,
impossible) to exploit.

Every indirect branch in a program has a purpose.  Using human intelligence,
a programmer can describe where a particular branch *should* go according to
this purpose: a ``return`` in ``printf`` should return to the call site,
a particular call in ``qsort`` should call the comparator that was passed in as
an argument, and so on.  But for CFI to enforce that every branch in a program
goes where it *should* in this sense would require CFI to perfectly enforce
every semantic rule of the program's abstract machine; that is, it would
require making the programming environment perfectly sound.  That is out of
scope.  Instead, the goal of CFI is merely to catch attempts to make a branch
go somewhere that it obviously *shouldn't* for its purpose: for example, to
stop a call from branching into the middle of a function rather than its
beginning.  As the information available to CFI gets better about the purpose
of the branch, CFI can enforce tighter and tighter restrictions on where the
branch is permitted to go.  Still, ultimately CFI cannot make the program
sound.  This may help explain why pointer authentication makes some of the
choices it does: for example, to sign and authenticate mostly code pointers
rather than every pointer in the program.  Preventing attackers from
redirecting branches is both particularly important and particularly
approachable as a goal.  Detecting corruption more broadly is infeasible with
these techniques, and the attempt would have far higher cost.

Attacks on Pointer Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pointer authentication works as follows.  Every indirect branch in a program
has a purpose.  For every purpose, the implementation chooses a :ref:`signing
schema<Signing schemas>`.  At some place where a pointer is known to be correct
for its purpose, it is signed according to the purpose's schema.  At every
place where the pointer is needed for its purpose, it is authenticated
according to the purpose's schema.  If that authentication fails, the program
is halted.

There are a variety of ways to attack this.

Attacks of Interest to Programmers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These attacks arise from weaknesses in the default protections offered by
pointer authentication.  They can be addressed by using attributes or
intrinsics to opt in to stronger protection.

Substitution Attacks
++++++++++++++++++++

An attacker can simply overwrite a pointer intended for one purpose with
a pointer intended for another purpose if both purposes use the same signing
schema and that schema does not use address diversity.

The most common source of this weakness is when code relies on using the
default language rules for C function pointers.  The current implementation
uses the exact same signing schema for all C function pointers, even for
functions of substantially different type.  While efforts are ongoing to
improve constant diversity for C function pointers of different type, there are
necessary limits to this.  The C standard requires function pointers to be
copyable with ``memcpy``, which means that function pointers can never use
address diversity.  Furthermore, even if a function pointer can only be
replaced with another function of the exact same type, that can still be useful
to an attacker, as in the following example of a hand-rolled "v-table":

.. code-block:: c

  struct ObjectOperations {
    void (*retain)(Object *);
    void (*release)(Object *);
    void (*deallocate)(Object *);
    void (*logStatus)(Object *);
  };

This weakness can be mitigated by using a more specific signing schema for each
purpose.  For example, in this example, the ``__ptrauth`` qualifier can be used
with a different constant discriminator for each field.  Since there's no
particular reason it's important for this v-table to be copyable with
``memcpy``, the functions can also be signed with address diversity:

.. code-block:: c

  #if __has_feature(ptrauth_calls)
  #define objectOperation(discriminator) \
    __ptrauth(ptrauth_key_function_pointer, 1, discriminator)
  #else
  #define objectOperation(discriminator)
  #endif

  struct ObjectOperations {
    void (*objectOperation(0xf017) retain)(Object *);
    void (*objectOperation(0x2639) release)(Object *);
    void (*objectOperation(0x8bb0) deallocate)(Object *);
    void (*objectOperation(0xc5d4) logStatus)(Object *);
  };

This weakness can also sometimes be mitigated by simply keeping the signed
pointer in constant memory, but this is less effective than using better
signing diversity.

.. _Access path attacks:

Access Path Attacks
+++++++++++++++++++

If a signed pointer is often accessed indirectly (that is, by first loading the
address of the object where the signed pointer is stored), an attacker can
affect uses of it by overwriting the intermediate pointer in the access path.

The most common scenario exhibiting this weakness is an object with a pointer
to a "v-table" (a structure holding many function pointers). An attacker does
not need to replace a signed function pointer in the v-table if they can
instead simply replace the v-table pointer in the object with their own pointer
--- perhaps to memory where they've constructed their own v-table, or to
existing memory that coincidentally happens to contain a signed pointer at the
right offset that's been signed with the right signing schema.

This attack arises because data pointers are not signed by default. It works
even if the signed pointer uses address diversity: address diversity merely
means that each pointer is signed with its own storage address, which (by
design) is invariant to changes in the accessing pointer.

Using sufficiently diverse signing schemas within the v-table can provide
reasonably strong mitigation against this weakness.  Always use address
diversity in v-tables to prevent attackers from assembling their own v-table.
Avoid re-using constant discriminators to prevent attackers from replacing
a v-table pointer with a pointer to totally unrelated memory that just happens
to contain an similarly-signed pointer.

Further mitigation can be attained by signing pointers to v-tables. Any
signature at all should prevent attackers from forging v-table pointers; they
will need to somehow harvest an existing signed pointer from elsewhere in
memory.  Using a meaningful constant discriminator will force this to be
harvested from an object with similar structure (e.g. a different
implementation of the same interface).  Using address diversity will prevent
such harvesting entirely.  However, care must be taken when sourcing the
v-table pointer originally; do not blindly sign a pointer that is not
:ref:`safely derived<Safe derivation>`.

.. _Signing oracles:

Signing oracles
+++++++++++++++

A signing oracle is a code sequence which can be exploited by an attacker to
sign an arbitrary pointer in a way that can later be recovered.  Such oracles
can be used by attackers to forge signatures matching the oracle's signing
schema, which is likely to cause a total compromise of pointer authentication's
effectiveness.

This attack only affects ordinary programmers if they are using certain
treacherous patterns of code.  Currently this includes:

- all uses of the ``__ptrauth_sign_unauthenticated`` intrinsic and
- assigning data pointers to ``__ptrauth``-qualified l-values.

Care must be taken in these situations to ensure that the pointer being signed
has been :ref:`safely derived<Safe derivation>` or is otherwise not possible to
attack.  (In some cases, this may be challenging without compiler support.)

A diagnostic will be added in the future for implicitly dangerous patterns of
code, such as assigning a non-safely-derived data pointer to
a ``__ptrauth``-qualified l-value.

.. _Authentication oracles:

Authentication Oracles
++++++++++++++++++++++

An authentication oracle is a code sequence which can be exploited by an
attacker to leak whether a signed pointer is validly signed without halting the
program if it isn't.  Such oracles can be used to forge signatures matching the
oracle's signing schema if the attacker can repeatedly invoke the oracle for
different candidate signed pointers. This is likely to cause a total compromise
of pointer authentication's effectiveness.

There should be no way for an ordinary programmer to create an authentication
oracle using the current set of operations. However, implementation flaws in
the past have occasionally given rise to authentication oracles due to
a failure to immediately trap on authentication failure.

The likelihood of creating an authentication oracle is why there is currently
no intrinsic which queries whether a signed pointer is validly signed.


Attacks of Interest to Implementors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These attacks are not inherent to the model; they arise from mistakes in either
implementing or using the `sign` and `auth` operations. Avoiding these mistakes
requires careful work throughout the system.

Failure to Trap on Authentication Failure
+++++++++++++++++++++++++++++++++++++++++

Any failure to halt the program on an authentication failure is likely to be
exploitable by attackers to create an :ref:`authentication
oracle<Authentication oracles>`.

There are several different ways to introduce this problem:

- The implementation might try to halt the program in some way that can be
  intercepted.

  For example, the ``auth`` instruction in Armv8.3 does not directly trap;
  instead it corrupts its result so that it is always an invalid pointer. If
  the program subsequently attempts to use that pointer, that will be a bad
  memory access, and it will trap into the kernel.  However, kernels do not
  usually immediately halt programs that trigger traps due to bad memory
  accesses; instead they notify the process to give it an opportunity to
  recover.  If this happens with an ``auth`` failure, the attacker may be able
  to exploit the recovery path in a way that creates an oracle. Kernels should
  ensure that these sorts of traps are not recoverable.

- A compiler might use an intermediate representation (IR) for ``sign`` and
  ``auth`` operations that cannot make adequate correctness guarantees.

  For example, suppose that an IR uses Armv8.3-like semantics for ``auth``: the
  operation merely corrupts its result on failure instead of promising the
  trap.  A frontend might emit patterns of IR that always follow an ``auth``
  with a memory access, thinking that this ensures correctness. But if the IR
  can be transformed to insert code between the ``auth`` and the access, or if
  the ``auth`` can be speculated, then this potentially creates an oracle.  It
  is better for ``auth`` to semantically guarantee to trap, potentially
  requiring an explicit check in the generated code. An Armv8.3-like target can
  avoid this explicit check in the common case by recognizing the pattern of an
  ``auth`` followed immediately by an access.

Attackable Code Sequences
+++++++++++++++++++++++++

If code that is part of a pointer authentication operation is interleaved with
code that may itself be vulnerable to attacks, an attacker may be able to use
this to create a :ref:`signing<Signing oracles>` or
:ref:`authentication<Authentication oracles>` oracle.

For example, suppose that the compiler is generating a call to a function and
passing two arguments: a signed constant pointer and a value derived from
a call.  In Armv8.3, this code might look like so:

.. code-block:: asm

  adr x19, _callback.        ; compute &_callback
  paciza x19                 ; sign it with a constant discriminator of 0
  blr _argGenerator          ; call _argGenerator() (returns in x0)
  mov x1, x0                 ; move call result to second arg register
  mov x0, x19                ; move signed &_callback to first arg register
  blr _function              ; call _function

This code is correct, as would be a sequencing that does *both* the ``adr`` and
the ``paciza`` after the call to ``_argGenerator``.  But a sequence that
computes the address of ``_callback`` but leaves it as a raw pointer in
a register during the call to ``_argGenerator`` would be vulnerable:

.. code-block:: asm

  adr x19, _callback.        ; compute &_callback
  blr _argGenerator          ; call _argGenerator() (returns in x0)
  mov x1, x0                 ; move call result to second arg register
  paciza x19                 ; sign &_callback
  mov x0, x19                ; move signed &_callback to first arg register
  blr _function              ; call _function

If ``_argGenerator`` spills ``x19`` (a callee-save register), and if the
attacker can perform a write during this call, then the attacker can overwrite
the spill slot with an arbitrary pointer that will eventually be
unconditionally signed after the function returns.  This would be a signing
oracle.

The implementation can avoid this by obeying two basic rules:

- The compiler's intermediate representations (IR) should not provide
  operations that expose intermediate raw pointers.  This may require providing
  extra operations that perform useful combinations of operations.

  For example, there should be an "atomic" auth-and-resign operation that
  should be used instead of emitting an ``auth`` operation whose result is fed
  into a ``sign``.

  Similarly, if a pointer should be authenticated as part of doing a memory
  access or a call, then the access or call should be decorated with enough
  information to perform the authentication; there should not be a separate
  ``auth`` whose result is used as the pointer operand for the access or call.
  (In LLVM IR, we do this for calls, but not yet for loads or stores.)

  "Operations" includes things like materializing a signed pointer to a known
  function or global variable.  The compiler must be able to recognize and emit
  this as a unified operation, rather than potentially splitting it up as in
  the example above.

- The compiler backend should not be too aggressive about scheduling
  instructions that are part of a pointer authentication operation.  This may
  require custom code-generation of these operations in some cases.

Register Clobbering
+++++++++++++++++++

As a refinement of the section on `Attackable code sequences`_, if the attacker
has the ability to modify arbitrary *register* state at arbitrary points in the
program, then special care must be taken.

For example, Armv8.3 might materialize a signed function pointer like so:

.. code-block:: asm

  adr x0, _callback.        ; compute &_callback
  paciza x0                 ; sign it with a constant discriminator of 0

If an attacker has the ability to overwrite ``x0`` between these two
instructions, this code sequence is vulnerable to becoming a signing oracle.

For the most part, this sort of attack is not possible: it is a basic element
of the design of modern computation that register state is private and
inviolable.  However, in systems that support asynchronous interrupts, this
property requires the cooperation of the interrupt-handling code. If that code
saves register state to memory, and that memory can be overwritten by an
attacker, then essentially the attack can overwrite arbitrary register state at
an arbitrary point.  This could be a concern if the threat model includes
attacks on the kernel or if the program uses user-space preemptive
multitasking.

(Readers might object that an attacker cannot rely on asynchronous interrupts
triggering at an exact instruction boundary.  In fact, researchers have had
some success in doing exactly that.  Even ignoring that, though, we should aim
to protect against lucky attackers just as much as good ones.)

To protect against this, saved register state must be at least partially signed
(using something like `ptrauth_sign_generic_data`_).  This is required for
correctness anyway because saved thread states include security-critical
registers such as SP, FP, PC, and LR (where applicable).  Ideally, this
signature would cover all the registers, but since saving and restoring
registers can be very performance-sensitive, that may not be acceptable. It is
sufficient to set aside a small number of scratch registers that will be
guaranteed to be preserved correctly; the compiler can then be careful to only
store critical values like intermediate raw pointers in those registers.

``setjmp`` and ``longjmp`` should sign and authenticate the core registers (SP,
FP, PC, and LR), but they do not need to worry about intermediate values
because ``setjmp`` can only be called synchronously, and the compiler should
never schedule pointer-authentication operations interleaved with arbitrary
calls.

.. _Relative addresses:

Attacks on Relative Addressing
++++++++++++++++++++++++++++++

Relative addressing is a technique used to compress and reduce the load-time
cost of infrequently-used global data.  The pointer authentication system is
unlikely to support signing or authenticating a relative address, and in most
cases it would defeat the point to do so: it would take additional storage
space, and applying the signature would take extra work at load time.

Relative addressing is not precluded by the use of pointer authentication, but
it does take extra considerations to make it secure:

- Relative addresses must only be stored in read-only memory.  A writable
  relative address can be overwritten to point nearly anywhere, making it
  inherently insecure; this danger can only be compensated for with techniques
  for protecting arbitrary data like `ptrauth_sign_generic_data`_.

- Relative addresses must only be accessed through signed pointers with
  adequate diversity.  If an attacker can perform an `access path attack` to
  replace the pointer through which the relative address is accessed, they can
  easily cause the relative address to point wherever they want.

Signature Forging
+++++++++++++++++

If an attacker can exactly reproduce the behavior of the signing algorithm, and
they know all the correct inputs to it, then they can perfectly forge
a signature on an arbitrary pointer.

There are three components to avoiding this mistake:

- The abstract signing algorithm should be good: it should not have glaring
  flaws which would allow attackers to predict its result with better than
  random accuracy without knowing all the inputs (like the key values).

- The key values should be kept secret.  If at all possible, they should never
  be stored in accessible memory, or perhaps only stored encrypted.

- Contexts that are meant to be independently protected should use different
  key values.  For example, the kernel should not use the same keys as user
  processes.  Different user processes should also use different keys from each
  other as much as possible, although this may pose its own technical
  challenges.

Remapping
+++++++++

If an attacker can change the memory protections on certain pages of the
program's memory, that can substantially weaken the protections afforded by
pointer authentication.

- If an attacker can inject their own executable code, they can also certainly
  inject code that can be used as a :ref:`signing oracle<Signing Oracles>`.
  The same is true if they can write to the instruction stream.

- If an attacker can remap read-only program sections to be writable, then any
  use of :ref:`relative addresses` in global data becomes insecure.

- If an attacker can remap read-only program sections to be writable, then it
  is unsafe to use unsigned pointers in global offset tables.

Remapping memory in this way often requires the attacker to have already
substantively subverted the control flow of the process.  Nonetheless, if the
operating system has a mechanism for mapping pages in a way that cannot be
remapped, this should be used wherever possible.



.. _Safe Derivation:

Safe Derivation
~~~~~~~~~~~~~~~

Whether a data pointer is stored, even briefly, as a raw pointer can affect the
security-correctness of a program.  (Function pointers are never implicitly
stored as raw pointers; raw pointers to functions can only be produced with the
``<ptrauth.h>`` intrinsics.)  Repeated re-signing can also impact performance.
Clang makes a modest set of guarantees in this area:

- An expression of pointer type is said to be **safely derived** if:

  - it takes the address of a global variable or function, or

  - it is a load from a gl-value of ``__ptrauth``-qualified type.

- If a value that is safely derived is assigned to a ``__ptrauth``-qualified
  object, including by initialization, then the value will be directly signed
  as appropriate for the target qualifier and will not be stored as a raw
  pointer.

- If the function expression of a call is a gl-value of ``__ptrauth``-qualified
  type, then the call will be authenticated directly according to the source
  qualifier and will not be resigned to the default rule for a function pointer
  of its type.

These guarantees are known to be inadequate for data pointer security. In
particular, Clang should be enhanced to make the following guarantees:

- A pointer should additionally be considered safely derived if it is:

  - the address of a gl-value that is safely derived,

  - the result of pointer arithmetic on a pointer that is safely derived (with
    some restrictions on the integer operand),

  - the result of a comma operator where the second operand is safely derived,

  - the result of a conditional operator where the selected operand is safely
    derived, or

  - the result of loading from a safely derived gl-value.

- A gl-value should be considered safely derived if it is:

  - a dereference of a safely derived pointer,

  - a member access into a safely derived gl-value, or

  - a reference to a variable.

- An access to a safely derived gl-value should be guaranteed to not allow
  replacement of any of the safely-derived component values at any point in the
  access.  "Access" should include loading a function pointer.

- Assignments should include pointer-arithmetic operators like ``+=``.

Making these guarantees will require further work, including significant new
support in LLVM IR.

Furthermore, Clang should implement a warning when assigning a data pointer
that is not safely derived to a ``__ptrauth``-qualified gl-value.



Alternative Implementations
---------------------------

Signature Storage
~~~~~~~~~~~~~~~~~

It is not critical for the security of pointer authentication that the
signature be stored "together" with the pointer, as it is in Armv8.3. An
implementation could just as well store the signature in a separate word, so
that the ``sizeof`` a signed pointer would be larger than the ``sizeof`` a raw
pointer.

Storing the signature in the high bits, as Armv8.3 does, has several trade-offs:

- Disadvantage: there are substantially fewer bits available for the signature,
  weakening the mitigation by making it much easier for an attacker to simply
  guess the correct signature.

- Disadvantage: future growth of the address space will necessarily further
  weaken the mitigation.

- Advantage: memory layouts don't change, so it's possible for
  pointer-authentication-enabled code (for example, in a system library) to
  efficiently interoperate with existing code, as long as pointer
  authentication can be disabled dynamically.

- Advantage: the size of a signed pointer doesn't grow, which might
  significantly increase memory requirements, code size, and register pressure.

- Advantage: the size of a signed pointer is the same as a raw pointer, so
  generic APIs which work in types like `void *` (such as `dlsym`) can still
  return signed pointers.  This means that clients of these APIs will not
  require insecure code in order to correctly receive a function pointer.

Hashing vs. Encrypting Pointers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Armv8.3 implements ``sign`` by computing a cryptographic hash and storing that
in the spare bits of the pointer.  This means that there are relatively few
possible values for the valid signed pointer, since the bits corresponding to
the raw pointer are known.  Together with an ``auth`` oracle, this can make it
computationally feasible to discover the correct signature with brute force.
(The implementation should of course endeavor not to introduce ``auth``
oracles, but this can be difficult, and attackers can be devious.)

If the implementation can instead *encrypt* the pointer during ``sign`` and
*decrypt* it during ``auth``, this brute-force attack becomes far less
feasible, even with an ``auth`` oracle.  However, there are several problems
with this idea:

- It's unclear whether this kind of encryption is even possible without
  increasing the storage size of a signed pointer.  If the storage size can be
  increased, brute-force atacks can be equally well mitigated by simply storing
  a larger signature.

- It would likely be impossible to implement a ``strip`` operation, which might
  make debuggers and other out-of-process tools far more difficult to write, as
  well as generally making primitive debugging more challenging.

- Implementations can benefit from being able to extract the raw pointer
  immediately from a signed pointer.  An Armv8.3 processor executing an
  ``auth``-and-load instruction can perform the load and ``auth`` in parallel;
  a processor which instead encrypted the pointer would be forced to perform
  these operations serially.
