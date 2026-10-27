; RUN: %opt_aflgo_linker -beacon-entry-pruning -passes='instrument-linker-aflgo' -S %s | %FileCheck %s

; An unsigned bound near the maximum integer is copied without arithmetic.
; CHECK-LABEL: define i32 @LLVMFuzzerTestOneInput
; CHECK: beacon.check:
; CHECK: icmp ule i64 %len, -2
; CHECK: beacon.decision:
define i32 @LLVMFuzzerTestOneInput(ptr %data, i64 %len) {
entry:
  %bounded = icmp ule i64 %len, -2
  br i1 %bounded, label %call, label %done
call:
  call void @target()
  br label %done
done:
  ret i32 0
}

define void @target() {
entry:
  call void @__aflgo_trace_bb_target(i32 0)
  ret void
}

declare void @__aflgo_trace_bb_target(i32)
