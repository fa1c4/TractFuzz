#include <AFLGoLinker/SelectFuzz.hpp>
#include <Analysis/SelectFuzz.hpp>

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <cmath>
#include <limits>
#include <memory>
#include <system_error>

using namespace llvm;

PreservedAnalyses SelectFuzzInstrumentationPass::run(Module &M,
                                                      ModuleAnalysisManager &MAM) {
  auto &R = MAM.getResult<SelectFuzzAnalysis>(M);
  auto &C = M.getContext();
  auto Trace = M.getOrInsertFunction("__selectfuzz_trace_bb",
                                     Type::getVoidTy(C), Type::getInt32Ty(C),
                                     Type::getInt64Ty(C));
  std::unique_ptr<raw_fd_ostream> Manifest;
  if (!ManifestFile.empty()) {
    std::error_code EC;
    Manifest = std::make_unique<raw_fd_ostream>(ManifestFile, EC, sys::fs::OF_Text);
    if (EC) report_fatal_error(Twine("SelectFuzz manifest: ") + EC.message());
    *Manifest << "# selectfuzz-blocks-v1\n"
                 "id\tfunction\tbb_index\tkind\tprobability\tdistance_milli\tlocation\n";
  }
  uint32_t NextID = 1;
  uint64_t Total = 0, Selected = 0;
  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    unsigned BBIndex = 0;
    for (auto &BB : F) {
      ++Total;
      auto Kind = R.Kinds.lookup(&BB);
      double P = R.Probability.lookup(&BB);
      uint64_t Distance = 0;
      uint32_t ID = 0;
      if (Kind) {
        ++Selected;
        ID = NextID++;
        if (P > 0) {
          double Scaled = std::ceil(1000.0 / P);
          Distance = Scaled >= static_cast<double>(std::numeric_limits<uint64_t>::max())
                         ? std::numeric_limits<uint64_t>::max() : static_cast<uint64_t>(Scaled);
        }
        IRBuilder<> B(&*BB.getFirstInsertionPt());
        B.CreateCall(Trace, {B.getInt32(ID), B.getInt64(Distance)});
      }
      if (Manifest) {
        std::string Location = "?";
        for (auto &I : BB)
          if (auto Loc = I.getDebugLoc()) {
            Location = (Loc->getDirectory() + "/" + Loc->getFilename()).str()
                       + ":" + std::to_string(Loc.getLine());
            break;
          }
        *Manifest << ID << '\t' << F.getName() << '\t' << BBIndex << '\t'
                  << static_cast<unsigned>(Kind) << '\t' << P << '\t'
                  << Distance << '\t' << Location << '\n';
      }
      ++BBIndex;
    }
  }
  errs() << "[SelectFuzz] selected " << Selected << '/' << Total
         << " blocks; unresolved indirect calls=" << R.IndirectCallsWithoutTargets
         << "; unknown memory loads=" << R.UnknownMemoryLoads
         << "; slice truncated=" << R.SliceTruncated << '\n';
  return PreservedAnalyses::none();
}
