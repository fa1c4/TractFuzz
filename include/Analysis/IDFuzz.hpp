#pragma once

#include <llvm/IR/PassManager.h>
#include <vector>

namespace llvm {
class BasicBlock;
class Module;

class IDFuzzAnalysis : public AnalysisInfoMixin<IDFuzzAnalysis> {
public:
  struct Step {
    BasicBlock *Block;
    unsigned Target;
    unsigned Depth;
    bool Terminal;
    bool SiteEntry;
    bool Callsite;
  };
  struct Result {
    std::vector<Step> Steps;
    unsigned Targets = 0;
    unsigned TargetCalls = 0;
    unsigned IndirectCalls = 0;
    unsigned TerminalTargets = 0;
  };
  static AnalysisKey Key;
  Result run(Module &M, ModuleAnalysisManager &MAM);
};
}
