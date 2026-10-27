#pragma once

#include <llvm/IR/PassManager.h>

namespace llvm {

// A conservative BEACON adaptation: infer necessary comparisons on entry
// arguments and evaluate them before any target code runs.
class BeaconEntryPruningPass
    : public PassInfoMixin<BeaconEntryPruningPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

} // namespace llvm
