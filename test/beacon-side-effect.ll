; RUN: %opt_aflgo_linker -beacon-entry-pruning -passes='instrument-linker-aflgo' -S %s | %FileCheck %s

; The no-target branch stores state, so an in-process return would change
; later inputs. No guard may be inserted.
; CHECK-LABEL: define i32 @LLVMFuzzerTestOneInput
; CHECK-NEXT: entry:
; CHECK-NOT: beacon.check:
@state = global i32 0
define i32 @LLVMFuzzerTestOneInput(ptr %data, i64 %len) {
entry:
  %large = icmp uge i64 %len, 4
  br i1 %large, label %call, label %discard
call:
  call void @target()
  ret i32 0
discard:
  store i32 1, ptr @state
  ret i32 0
}

define void @target() {
entry:
  call void @__aflgo_trace_bb_target(i32 0)
  ret void
}

declare void @__aflgo_trace_bb_target(i32)
