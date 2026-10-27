#include <Analysis/IDFuzz.hpp>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/DenseMap.h>
#include <algorithm>
#include <map>
#include <memory>

using namespace llvm;
AnalysisKey IDFuzzAnalysis::Key;
using CallerMap = DenseMap<Function *, SmallVector<BasicBlock *, 8>>;
using DomCache = DenseMap<Function *, std::unique_ptr<DominatorTree>>;

static SmallVector<BasicBlock *, 64>
pathTo(BasicBlock *Leaf, const CallerMap &Callers, DomCache &Trees,
       SmallPtrSetImpl<Function *> &Seen,
       unsigned Remaining) {
  Function *F = Leaf->getParent();
  auto &Tree = Trees[F];
  if (!Tree) Tree = std::make_unique<DominatorTree>(*F);
  SmallVector<BasicBlock *, 64> Local;
  for (auto *Node = Tree->getNode(Leaf); Node; Node = Node->getIDom())
    Local.push_back(Node->getBlock());
  std::reverse(Local.begin(), Local.end());
  if (Remaining == 0 || !Seen.insert(F).second ||
      F->getName() == "main" || F->getName() == "LLVMFuzzerTestOneInput")
    return Local;
  SmallVector<BasicBlock *, 64> Best;
  auto Found = Callers.find(F);
  if (Found != Callers.end()) {
    for (BasicBlock *Caller : Found->second) {
      if (Seen.count(Caller->getParent())) continue;
      SmallPtrSet<Function *, 32> BranchSeen;
      BranchSeen.insert(Seen.begin(), Seen.end());
      auto Parent = pathTo(Caller, Callers, Trees, BranchSeen, Remaining - 1);
      if (Parent.size() > Best.size()) Best = std::move(Parent);
    }
  }
  if (!Best.empty()) {
    Best.append(Local.begin(), Local.end());
    return Best;
  }
  return Local;
}

IDFuzzAnalysis::Result IDFuzzAnalysis::run(Module &M, ModuleAnalysisManager &) {
  Result R;
  std::map<uint64_t, SmallVector<BasicBlock *, 8>> TargetSites;
  CallerMap Callers;
  DomCache Trees;
  uint64_t DynamicID = 1ull << 32;
  for (Function &F : M) {
    if (F.isDeclaration()) continue;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *Call = dyn_cast<CallBase>(&I);
        if (!Call) continue;
        Function *Callee = Call->getCalledFunction();
        if (!Callee) { ++R.IndirectCalls; continue; }
        if (!Callee->isDeclaration()) Callers[Callee].push_back(&BB);
        if (Callee->getName() != "__aflgo_trace_bb_target") continue;
        ++R.TargetCalls;
        auto *ID = dyn_cast<ConstantInt>(Call->getArgOperand(0));
        TargetSites[ID ? ID->getZExtValue() : DynamicID++].push_back(&BB);
      }
    }
  }
  for (auto &Group : TargetSites) {
    ++R.Targets;
    DenseMap<BasicBlock *, unsigned> Index;
    bool Terminal = false;
    for (BasicBlock *Site : Group.second) {
      Terminal |= succ_empty(Site);
      SmallPtrSet<Function *, 32> Seen;
      auto Chain = pathTo(Site, Callers, Trees, Seen, 16);
      for (unsigned Depth = 0; Depth < Chain.size(); ++Depth) {
        BasicBlock *BB = Chain[Depth];
        bool SiteEntry = BB == &Site->getParent()->getEntryBlock();
        bool Callsite = BB == Site;
        auto Found = Index.find(BB);
        if (Found == Index.end()) {
          Index[BB] = R.Steps.size();
          R.Steps.push_back({BB, R.Targets, Depth, false, SiteEntry, Callsite});
        } else {
          auto &Step = R.Steps[Found->second];
          Step.Depth = std::min(Step.Depth, Depth);
          Step.SiteEntry |= SiteEntry;
          Step.Callsite |= Callsite;
        }
      }
    }
    R.TerminalTargets += Terminal;
    for (auto &Step : R.Steps)
      if (Step.Target == R.Targets) Step.Terminal = Terminal;
  }
  return R;
}
