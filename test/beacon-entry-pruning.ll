; RUN: %opt_aflgo_linker -beacon-entry-pruning -passes='instrument-linker-aflgo' -S %s | %FileCheck %s

; The entry comparison is necessary. The discarded branch immediately returns
; zero and has no memory access or side effects.
; CHECK-LABEL: define i32 @LLVMFuzzerTestOneInput
; CHECK: beacon.check:
; CHECK: icmp uge i64 %len, 4
; CHECK: br i1 {{.*}}, label {{.*}}, label %beacon.decision
; CHECK: beacon.decision:
; CHECK: call i1 @__beacon_should_prune
; CHECK: beacon.pruned:
; CHECK: ret i32 0
define i32 @LLVMFuzzerTestOneInput(ptr %data, i64 %len) {
entry:
  %large = icmp uge i64 %len, 4
  br i1 %large, label %call, label %done
call:
  call void @target()
  br label %done
done:
  ret i32 0
}

; Both arms reach the target, so no entry precondition is inferred.
; CHECK-LABEL: define i32 @main
; CHECK-NEXT: entry:
define i32 @main(i32 %argc, ptr %argv) {
entry:
  %cond = icmp sgt i32 %argc, 1
  br i1 %cond, label %left, label %right
left:
  call void @target()
  br label %done
right:
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
