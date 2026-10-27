; RUN: %opt_aflgo_linker -beacon-entry-pruning -passes='instrument-linker-aflgo' -S %s | %FileCheck %s

; The predicate reads mutable input memory, so the entry-only pass must not
; lift it into a pruning guard. This also prevents unsafe alias assumptions.
; CHECK-LABEL: define i32 @LLVMFuzzerTestOneInput
; CHECK-NEXT: entry:
; CHECK-NOT: beacon.check:
define i32 @LLVMFuzzerTestOneInput(ptr %data, i64 %len) {
entry:
  %byte = load i8, ptr %data
  %match = icmp eq i8 %byte, 65
  br i1 %match, label %call, label %done
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
