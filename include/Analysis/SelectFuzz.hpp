#pragma once

#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/PassManager.h>

#include <cstdint>

namespace llvm {

class SelectFuzzAnalysis : public AnalysisInfoMixin<SelectFuzzAnalysis> {
public:
  static AnalysisKey Key;

  enum Kind : uint8_t {
    None = 0,
    Divergent = 1,
    Data = 2,
    Target = 4,
    UncertainCall = 8,
  };

  struct Result {
    DenseMap<const BasicBlock *, uint8_t> Kinds;
    DenseMap<const BasicBlock *, double> Probability;
    unsigned IndirectCallsWithoutTargets = 0;
    unsigned UnknownMemoryLoads = 0;
    bool SliceTruncated = false;

    bool isRelevant(const BasicBlock *BB) const {
      return Kinds.lookup(BB) != None;
    }
  };

  explicit SelectFuzzAnalysis(bool ExtendedCG = false)
      : ExtendedCG(ExtendedCG) {}

  Result run(Module &M, ModuleAnalysisManager &MAM);

private:
  bool ExtendedCG;
};

} // namespace llvm
