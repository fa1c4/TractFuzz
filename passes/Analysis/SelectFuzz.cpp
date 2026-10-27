#include <Analysis/SelectFuzz.hpp>
#include <Analysis/ExtendedCallGraph.hpp>
#include <Analysis/TargetDetection.hpp>

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/Analysis/CallGraph.h>

#include <algorithm>
#include <cmath>
#include <deque>
#include <vector>

using namespace llvm;

AnalysisKey SelectFuzzAnalysis::Key;

SelectFuzzAnalysis::Result SelectFuzzAnalysis::run(Module &M,
                                                   ModuleAnalysisManager &MAM) {
  Result R;
  DenseMap<const BasicBlock *, SmallVector<const BasicBlock *, 4>> Succ, Pred;
  DenseMap<const BasicBlock *, unsigned> BlockOrder;
  SmallVector<const BasicBlock *, 128> OrderedBlocks;
  DenseMap<const Function *, SmallVector<const BasicBlock *, 4>> Returns;
  DenseMap<const Function *, SmallVector<const CallBase *, 4>> Calls;
  DenseMap<const Value *, SmallVector<const StoreInst *, 4>> Stores;
  SmallPtrSet<const BasicBlock *, 32> Targets;
  SmallVector<const Instruction *, 32> TargetInstructions;
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    auto &T = FAM.getResult<AFLGoTargetDetectionAnalysis>(F);
    for (auto &Pair : T.BBs) Targets.insert(Pair.first);
    for (auto *I : T.Is) TargetInstructions.push_back(I);
    for (auto &BB : F) {
      BlockOrder[&BB] = OrderedBlocks.size();
      OrderedBlocks.push_back(&BB);
      Succ[&BB];
      for (auto *Next : successors(&BB)) Succ[&BB].push_back(Next);
      if (isa<ReturnInst>(BB.getTerminator())) Returns[&F].push_back(&BB);
      for (auto &I : BB) {
        if (auto *Call = dyn_cast<CallBase>(&I)) {
          if (Call->getCalledFunction()) Calls[Call->getCalledFunction()].push_back(Call);
          else if (!isa<IntrinsicInst>(Call)) ++R.IndirectCallsWithoutTargets;
        }
        if (auto *Store = dyn_cast<StoreInst>(&I))
          Stores[Store->getPointerOperand()->stripPointerCasts()].push_back(Store);
      }
    }
  }
  // The static graph follows calls into definitions and returns to the caller's
  // CFG continuation. For a call inside a block, the block is the callsite.
  auto addCall = [&](const CallBase *Call, const Function *Callee) {
    if (!Callee || Callee->isDeclaration() || Callee->empty()) return;
    auto *Site = Call->getParent();
    Succ[Site].push_back(&Callee->getEntryBlock());
    for (auto *Ret : Returns[Callee])
      for (auto *Next : successors(Site)) Succ[Ret].push_back(Next);
  };
  for (auto &Entry : Calls)
    for (auto *Call : Entry.second) addCall(Call, Entry.first);
  if (ExtendedCG && R.IndirectCallsWithoutTargets) {
    auto &CG = MAM.getResult<ExtendedCallGraphAnalysis>(M);
    for (auto &F : M) {
      if (F.isDeclaration()) continue;
      auto *Node = CG[&F];
      if (!Node) continue;
      for (auto &Edge : *Node) {
        auto *Call = dyn_cast_or_null<CallBase>(Edge.first.getValue());
        if (Call && !Call->getCalledFunction() && Edge.second)
          addCall(Call, Edge.second->getFunction());
      }
    }
  }
  for (auto &Entry : Succ) {
    auto &V = Entry.second;
    std::sort(V.begin(), V.end(), [&](auto *A, auto *B) {
      return BlockOrder.lookup(A) < BlockOrder.lookup(B);
    });
    V.erase(std::unique(V.begin(), V.end()), V.end());
    for (auto *Next : V) Pred[Next].push_back(Entry.first);
  }

  SmallPtrSet<const BasicBlock *, 32> Reachable;
  SmallVector<const BasicBlock *, 32> Work;
  for (auto *BB : Targets) {
    R.Kinds[BB] |= Target;
    if (Reachable.insert(BB).second) Work.push_back(BB);
  }
  while (!Work.empty()) {
    auto *BB = Work.pop_back_val();
    for (auto *Prev : Pred[BB])
      if (Reachable.insert(Prev).second) Work.push_back(Prev);
  }
  for (auto &Entry : Succ) {
    bool Yes = false, No = false;
    for (auto *Next : Entry.second) {
      Yes |= Reachable.count(Next) != 0;
      No |= Reachable.count(Next) == 0;
    }
    if (Yes && No) R.Kinds[Entry.first] |= Divergent;
  }

  // Backward value slice from the actual annotated target instructions.
  // Direct stores to the same stripped pointer are included. Unresolved
  // memory/indirect calls are counted rather than silently called precise.
  SmallVector<const Value *, 64> Values;
  SmallPtrSet<const Value *, 32> Seen;
  for (auto *I : TargetInstructions) Values.push_back(I);
  for (auto *BB : Targets)
    if (TargetInstructions.empty()) Values.push_back(BB->getTerminator());
  unsigned Steps = 0;
  while (!Values.empty()) {
    if (++Steps > 2000000) { R.SliceTruncated = true; break; }
    auto *V = Values.pop_back_val();
    if (!V || !Seen.insert(V).second) continue;
    if (auto *I = dyn_cast<Instruction>(V)) {
      R.Kinds[I->getParent()] |= Data;
      if (auto *Load = dyn_cast<LoadInst>(I)) {
        auto *Pointer = Load->getPointerOperand()->stripPointerCasts();
        auto It = Stores.find(Pointer);
        if (It == Stores.end()) ++R.UnknownMemoryLoads;
        else for (auto *Store : It->second) Values.push_back(Store);
      }
      if (auto *Call = dyn_cast<CallBase>(I)) {
        if (auto *Callee = Call->getCalledFunction())
          for (auto *Ret : Returns[Callee])
            Values.push_back(cast<ReturnInst>(Ret->getTerminator())->getReturnValue());
      }
      for (auto &Op : I->operands()) Values.push_back(Op.get());
    } else if (auto *Arg = dyn_cast<Argument>(V)) {
      for (auto *Call : Calls[Arg->getParent()])
        if (Arg->getArgNo() < Call->arg_size())
          Values.push_back(Call->getArgOperand(Arg->getArgNo()));
    }
  }

  // Bellman updates approximate the paper's one-unroll DFS on recursive
  // graphs. 64 rounds bound cost for large LTO modules.
  for (auto *BB : Targets) R.Probability[BB] = 1.0;
  for (unsigned Round = 0; Round < 64; ++Round) {
    double Delta = 0;
    for (auto *BB : OrderedBlocks) {
      auto &NextBlocks = Succ[BB];
      if (Targets.count(BB) || !Reachable.count(BB) || NextBlocks.empty())
        continue;
      double P = 0;
      for (auto *Next : NextBlocks) P += R.Probability.lookup(Next);
      P /= NextBlocks.size();
      Delta = std::max(Delta, std::abs(P - R.Probability.lookup(BB)));
      R.Probability[BB] = P;
    }
    if (Delta < 1e-7) break;
  }
  return R;
}
