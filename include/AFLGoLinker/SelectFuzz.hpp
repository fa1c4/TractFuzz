#pragma once

#include <llvm/IR/PassManager.h>

#include <string>

namespace llvm {

class SelectFuzzInstrumentationPass
    : public PassInfoMixin<SelectFuzzInstrumentationPass> {
public:
  explicit SelectFuzzInstrumentationPass(std::string ManifestFile = "")
      : ManifestFile(std::move(ManifestFile)) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

private:
  std::string ManifestFile;
};

} // namespace llvm
