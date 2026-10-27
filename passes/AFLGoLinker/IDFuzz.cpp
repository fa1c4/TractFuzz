#include <AFLGoLinker/IDFuzz.hpp>
#include <Analysis/IDFuzz.hpp>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <algorithm>

using namespace llvm;

PreservedAnalyses IDFuzzInstrumentationPass::run(Module &M, ModuleAnalysisManager &MAM) {
  auto &R = MAM.getResult<IDFuzzAnalysis>(M);
  if (R.Targets > 16)
    report_fatal_error("IDFuzz supports at most 16 distinct targets per linked program");
  auto &C = M.getContext();
  auto Trace = M.getOrInsertFunction("__idfuzz_trace_dom", Type::getVoidTy(C),
                                     Type::getInt32Ty(C));
  auto BranchTrace = M.getOrInsertFunction("__idfuzz_trace_branch", Type::getVoidTy(C),
                                           Type::getInt32Ty(C), Type::getInt8Ty(C));
  const unsigned Budget = std::min(64u, 255u / std::max(1u, R.Targets));
  unsigned Omitted = 0;
  for (unsigned Target = 1; Target <= R.Targets; ++Target) {
    unsigned Count = 0;
    for (const auto &S : R.Steps) Count += S.Target == Target;
    if (Count > Budget) Omitted += Count - Budget;
  }
  std::unique_ptr<raw_fd_ostream> Out;
  if (!Manifest.empty()) {
    std::error_code EC;
    Out = std::make_unique<raw_fd_ostream>(Manifest, EC, sys::fs::OF_Text);
    if (EC) report_fatal_error(Twine("IDFuzz manifest: ") + EC.message());
    *Out << "# idfuzz-dom-v1; union of direct-call chains; targets=" << R.Targets
         << "; target_calls=" << R.TargetCalls
         << "; terminal=" << R.TerminalTargets << "; indirect="
         << R.IndirectCalls << "; omitted=" << Omitted << "\n"
            "id\ttarget\tdepth\tfunction\tblock\tterminal\tlocation\tsite_entry\tcallsite\n";
  }
  unsigned ID = 1;
  unsigned BranchProbes = 0;
  for (unsigned Target = 1; Target <= R.Targets; ++Target) {
    SmallVector<const IDFuzzAnalysis::Step *, 256> Chain;
    for (const auto &S : R.Steps)
      if (S.Target == Target) Chain.push_back(&S);
    unsigned Keep = std::min(Budget, static_cast<unsigned>(Chain.size()));
    SmallVector<unsigned, 128> Chosen;
    SmallVector<bool, 256> Included(Chain.size(), false);
    auto SelectPriority = [&](auto Predicate) {
      for (unsigned N = 0; N < Chain.size() && Chosen.size() < Keep; ++N)
        if (!Included[N] && Predicate(*Chain[N])) {
          Included[N] = true;
          Chosen.push_back(N);
        }
    };
    SelectPriority([](const auto &S) { return S.SiteEntry; });
    SelectPriority([](const auto &S) { return S.Callsite; });
    SmallVector<unsigned, 256> Optional;
    for (unsigned N = 0; N < Chain.size(); ++N)
      if (!Included[N]) Optional.push_back(N);
    unsigned Remaining = Keep - Chosen.size();
    for (unsigned N = 0; N < Remaining; ++N) {
      unsigned Position = Remaining == 1 ? Optional.size() / 2 :
                          N * (Optional.size() - 1) / (Remaining - 1);
      Chosen.push_back(Optional[Position]);
    }
    std::sort(Chosen.begin(), Chosen.end());
    SmallVector<std::pair<const IDFuzzAnalysis::Step *, unsigned>, 128> Selected;
    for (unsigned N : Chosen) {
    const auto &S = *Chain[N];
    IRBuilder<> B(&*S.Block->getFirstInsertionPt());
    B.CreateCall(Trace, B.getInt32(ID));
    Selected.push_back({&S, ID});
    if (Out) {
      std::string Loc = "?";
      for (Instruction &I : *S.Block)
        if (auto DL = I.getDebugLoc()) {
          Loc = (DL->getDirectory() + "/" + DL->getFilename()).str() +
                ":" + std::to_string(DL.getLine());
          break;
        }
      *Out << ID << '\t' << S.Target << '\t' << S.Depth << '\t'
           << S.Block->getParent()->getName() << '\t' << S.Block->getName()
           << '\t' << S.Terminal << '\t' << Loc << '\t'
           << S.SiteEntry << '\t' << S.Callsite << '\n';
    }
    ++ID;
    }
    for (unsigned N = 1; N < Selected.size(); ++N) {
      auto *Previous = Selected[N - 1].first->Block;
      auto *Next = Selected[N].first->Block;
      auto *Branch = dyn_cast<BranchInst>(Previous->getTerminator());
      if (!Branch || !Branch->isConditional()) continue;
      bool NonDomWhenTrue;
      if (Branch->getSuccessor(0) == Next) NonDomWhenTrue = false;
      else if (Branch->getSuccessor(1) == Next) NonDomWhenTrue = true;
      else continue;
      IRBuilder<> B(Branch);
      auto *Value = B.CreateSelect(Branch->getCondition(),
                                   B.getInt8(NonDomWhenTrue ? 128 : 0),
                                   B.getInt8(NonDomWhenTrue ? 0 : 128));
      B.CreateCall(BranchTrace, {B.getInt32(Selected[N].second), Value});
      ++BranchProbes;
      if (Out) *Out << "# branch\t" << Selected[N - 1].second << '\t'
                    << Selected[N].second << "\n";
    }
  }
  errs() << "[IDFuzz] targets=" << R.Targets << " target calls=" << R.TargetCalls
         << " local dominator steps="
         << R.Steps.size() << " terminal=" << R.TerminalTargets
         << " indirect calls=" << R.IndirectCalls << " omitted=" << Omitted
         << " branch probes=" << BranchProbes << '\n';
  return PreservedAnalyses::none();
}
