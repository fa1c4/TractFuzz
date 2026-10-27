#include <AFLGoLinker/Beacon.hpp>
#include <Analysis/TargetDetection.hpp>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;

namespace {

bool mayReachOrigin(BasicBlock *Start,
                    const SmallPtrSetImpl<BasicBlock *> &Origins) {
  SmallVector<BasicBlock *, 16> Worklist{Start};
  SmallPtrSet<BasicBlock *, 32> Seen;
  while (!Worklist.empty()) {
    BasicBlock *BB = Worklist.pop_back_val();
    if (!Seen.insert(BB).second)
      continue;
    if (Origins.contains(BB))
      return true;
    for (BasicBlock *Succ : successors(BB))
      Worklist.push_back(Succ);
  }
  return false;
}

bool isUnknownCall(const CallBase &CB) {
  const Function *Callee = CB.getCalledFunction();
  if (!Callee)
    return true;
  if (Callee->getName() ==
      AFLGoTargetDetectionAnalysis::TargetFunctionName)
    return false;
  return Callee->isDeclaration() && !Callee->isIntrinsic();
}

bool isEntry(const Function &F) {
  return F.getName() == "LLVMFuzzerTestOneInput";
}

// An in-process early return may skip instructions from earlier inputs only
// when the discarded branch has no observable work of its own. Reject memory
// reads too: skipping a faulting read would change sanitizer behavior.
bool isPureDiscardPath(BasicBlock *Start) {
  SmallVector<BasicBlock *, 16> Worklist{Start};
  SmallPtrSet<BasicBlock *, 32> Seen;
  while (!Worklist.empty()) {
    BasicBlock *BB = Worklist.pop_back_val();
    if (!Seen.insert(BB).second)
      continue;
    for (Instruction &I : *BB) {
      if (I.isTerminator()) {
        if (!isa<BranchInst>(I) && !isa<SwitchInst>(I) &&
            !isa<ReturnInst>(I))
          return false;
        if (const auto *Ret = dyn_cast<ReturnInst>(&I)) {
          const Value *Value = Ret->getReturnValue();
          if (Value && !isa<ConstantAggregateZero>(Value) &&
              !isa<ConstantPointerNull>(Value) &&
              !isa<ConstantInt>(Value))
            return false;
          if (const auto *Int = dyn_cast_or_null<ConstantInt>(Value))
            if (!Int->isZero())
              return false;
        }
      } else if (isa<AllocaInst>(I) || I.mayHaveSideEffects() ||
                 I.mayReadFromMemory()) {
        return false;
      }
    }
    for (BasicBlock *Succ : successors(BB))
      Worklist.push_back(Succ);
  }
  return true;
}

struct Guard {
  ICmpInst *Compare;
  bool RequiredTrue;
};

} // namespace

PreservedAnalyses
BeaconEntryPruningPass::run(Module &M, ModuleAnalysisManager &MAM) {
  auto &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  DenseMap<Function *, bool> CanReachTarget;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    const auto &Targets = FAM.getResult<AFLGoTargetDetectionAnalysis>(F);
    bool MayReach = !Targets.BBs.empty();
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (const auto *CB = dyn_cast<CallBase>(&I))
          MayReach |= isUnknownCall(*CB);
    CanReachTarget[&F] = MayReach;
  }

  // Propagate known target and unknown-call reachability through direct calls.
  bool Changed;
  do {
    Changed = false;
    for (Function &F : M) {
      if (F.isDeclaration() || CanReachTarget.lookup(&F))
        continue;
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (!CB)
            continue;
          Function *Callee = CB->getCalledFunction();
          if (Callee && CanReachTarget.lookup(Callee)) {
            CanReachTarget[&F] = true;
            Changed = true;
            break;
          }
        }
        if (CanReachTarget.lookup(&F))
          break;
      }
    }
  } while (Changed);

  unsigned GuardID = 0;
  bool Modified = false;
  for (Function &F : M) {
    if (F.isDeclaration() || !isEntry(F) ||
        F.getEntryBlock().hasAddressTaken())
      continue;
    BasicBlock &OldEntry = F.getEntryBlock();
    if (isa<PHINode>(OldEntry.begin()))
      continue;

    SmallPtrSet<BasicBlock *, 32> Origins;
    const auto &Targets = FAM.getResult<AFLGoTargetDetectionAnalysis>(F);
    for (const auto &Target : Targets.BBs)
      Origins.insert(Target.first);
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (const auto *CB = dyn_cast<CallBase>(&I)) {
          const Function *Callee = CB->getCalledFunction();
          if (isUnknownCall(*CB) ||
              (Callee && CanReachTarget.lookup(Callee)))
            Origins.insert(&BB);
        }
    if (Origins.empty())
      continue;

    const auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);
    SmallVector<Guard, 8> Guards;
    for (BasicBlock &BB : F) {
      if (&BB != &OldEntry)
        continue;
      if (Origins.contains(&BB))
        continue;
      auto *Branch = dyn_cast<BranchInst>(BB.getTerminator());
      if (!Branch || !Branch->isConditional())
        continue;
      bool PurePrefix = true;
      for (Instruction &I : BB) {
        if (&I == Branch)
          break;
        if (isa<AllocaInst>(I) || I.mayHaveSideEffects() ||
            I.mayReadFromMemory()) {
          PurePrefix = false;
          break;
        }
      }
      if (!PurePrefix)
        continue;
      auto *Compare = dyn_cast<ICmpInst>(Branch->getCondition());
      if (!Compare)
        continue;
      const Value *Left = Compare->getOperand(0);
      const Value *Right = Compare->getOperand(1);
      const Argument *Arg = dyn_cast<Argument>(Left);
      const ConstantInt *Constant = dyn_cast<ConstantInt>(Right);
      if (!Arg || !Constant) {
        Arg = dyn_cast<Argument>(Right);
        Constant = dyn_cast<ConstantInt>(Left);
      }
      if (!Arg || !Constant || Arg->getParent() != &F)
        continue;
      bool DominatesAll = true;
      for (BasicBlock *Origin : Origins)
        if (!DT.dominates(&BB, Origin)) {
          DominatesAll = false;
          break;
        }
      if (!DominatesAll)
        continue;
      bool TrueCanReach = mayReachOrigin(Branch->getSuccessor(0), Origins);
      bool FalseCanReach = mayReachOrigin(Branch->getSuccessor(1), Origins);
      if (TrueCanReach == FalseCanReach)
        continue;
      BasicBlock *Discard =
          Branch->getSuccessor(TrueCanReach ? 1 : 0);
      if (!isPureDiscardPath(Discard))
        continue;
      Guards.push_back({Compare, TrueCanReach});
    }
    if (Guards.empty())
      continue;

    LLVMContext &C = M.getContext();
    BasicBlock *CheckBB = BasicBlock::Create(C, "beacon.check", &F, &OldEntry);
    BasicBlock *DecisionBB =
        BasicBlock::Create(C, "beacon.decision", &F, &OldEntry);
    BasicBlock *PruneBB = BasicBlock::Create(C, "beacon.pruned", &F, &OldEntry);
    IRBuilder<> Check(CheckBB);
    Value *Allowed = ConstantInt::getTrue(C);
    for (const Guard &G : Guards) {
      Value *Condition = Check.CreateICmp(
          G.Compare->getPredicate(), G.Compare->getOperand(0),
          G.Compare->getOperand(1), "beacon.required");
      if (!G.RequiredTrue)
        Condition = Check.CreateNot(Condition);
      Allowed = Check.CreateAnd(Allowed, Condition);
    }
    Check.CreateCondBr(Allowed, &OldEntry, DecisionBB);

    FunctionCallee ShouldPrune = M.getOrInsertFunction(
        "__beacon_should_prune", Type::getInt1Ty(C), Type::getInt32Ty(C));
    IRBuilder<> Decision(DecisionBB);
    Value *Prune = Decision.CreateCall(
        ShouldPrune, ConstantInt::get(Type::getInt32Ty(C), ++GuardID));
    Decision.CreateCondBr(Prune, PruneBB, &OldEntry);
    IRBuilder<> Return(PruneBB);
    if (F.getReturnType()->isVoidTy())
      Return.CreateRetVoid();
    else
      Return.CreateRet(Constant::getNullValue(F.getReturnType()));
    errs() << "[BEACON] entry " << F.getName() << ": "
           << Guards.size() << " necessary comparisons, guard "
           << GuardID << "\n";
    for (const Guard &G : Guards) {
      errs() << "[BEACON] guard " << GuardID << " requires "
             << (G.RequiredTrue ? "true" : "false") << " for "
             << *G.Compare << "\n";
    }
    Modified = true;
  }
  return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
