#pragma once
#include <llvm/IR/PassManager.h>
#include <string>

namespace llvm {
class IDFuzzInstrumentationPass : public PassInfoMixin<IDFuzzInstrumentationPass> {
  std::string Manifest;
public:
  explicit IDFuzzInstrumentationPass(std::string Path) : Manifest(std::move(Path)) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
}
