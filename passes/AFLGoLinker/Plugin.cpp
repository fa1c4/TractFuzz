#include <AFLGoLinker/DAFL.hpp>
#include <AFLGoLinker/Beacon.hpp>
#include <AFLGoLinker/SelectFuzz.hpp>
#include <AFLGoLinker/IDFuzz.hpp>
#include <AFLGoLinker/DistanceInstrumentation.hpp>
#include <AFLGoLinker/DuplicateTargetRemoval.hpp>
#include <AFLGoLinker/FunctionDistanceInstrumentation.hpp>
#include <AFLGoLinker/TargetInjectionFixup.hpp>

#include <Analysis/BasicBlockDistance.hpp>
#include <Analysis/DAFL.hpp>
#include <Analysis/SelectFuzz.hpp>
#include <Analysis/IDFuzz.hpp>
#include <Analysis/ExtendedCallGraph.hpp>
#include <Analysis/FunctionDistance.hpp>
#include <Analysis/TargetDetection.hpp>

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Transforms/Instrumentation.h>
#include <llvm/Transforms/Instrumentation/SanitizerCoverage.h>

using namespace llvm;

static cl::opt<bool> ClExtendCG(
    "extend-cg",
    cl::desc("Extend call graph with indirect edges through pointer analysis"),
    cl::init(false));

static cl::opt<bool>
    ClHawkeyeDistance("use-hawkeye-distance",
                      cl::desc("Use Hawkeye function distance definition"),
                      cl::init(false));

static cl::opt<bool>
    ClTraceFunctionDistance("trace-function-distance",
                            cl::desc("Add function distance tracing callbacks"),
                            cl::init(false));

static cl::opt<bool> ClDAFL("dafl", cl::desc("Enable DAFL instrumentation"),
                            cl::init(false));

static cl::opt<bool> ClSelectFuzz("selectfuzz",
                                cl::desc("Enable selective SelectFuzz feedback"),
                                cl::init(false));
static cl::opt<std::string> ClSelectFuzzManifest(
    "selectfuzz-manifest", cl::desc("Versioned SelectFuzz block manifest"),
    cl::init(""));

static cl::opt<bool> ClIDFuzz("idfuzz", cl::desc("Enable IDFuzz dominator probes"),
                             cl::init(false));
static cl::opt<std::string> ClIDFuzzManifest(
    "idfuzz-manifest", cl::desc("Versioned IDFuzz dominator manifest"), cl::init(""));

static cl::opt<bool> ClBeaconEntryPruning(
    "beacon-entry-pruning",
    cl::desc("Enable conservative BEACON entry precondition checks"),
    cl::init(false));

static cl::opt<bool> ClDAFLNoTargetsNoError(
    "dafl-targets-no-error",
    cl::desc("Don't error out if DAFL targets are not found"), cl::init(false));

static cl::opt<bool>
    ClDAFLDebug("dafl-debug",
                cl::desc("Save debug files for DAFL instrumentation"),
                cl::init(false));

static cl::opt<bool>
    ClDAFLVerbose("dafl-verbose",
                  "Enable verbose output for DAFL instrumentation",
                  cl::init(false));

static cl::opt<std::string>
    ClDAFLInputFile("dafl-input-file",
                    cl::desc("Input file for DAFL analysis results"),
                    cl::value_desc("filename"));

static cl::opt<std::string>
    ClDAFLOutputFile("dafl-output-file",
                     cl::desc("Output file for DAFL analysis results"),
                     cl::value_desc("filename"));

static void addPasses(ModulePassManager &MPM) {
  MPM.addPass(DuplicateTargetRemovalPass());

  if (ClBeaconEntryPruning)
    MPM.addPass(BeaconEntryPruningPass());

  if (ClSelectFuzz) {
    MPM.addPass(SelectFuzzInstrumentationPass(ClSelectFuzzManifest));
  } else if (ClDAFL) {
    MPM.addPass(DAFLInstrumentationPass(ClDAFLOutputFile));
  } else {
    if (ClTraceFunctionDistance) {
      MPM.addPass(FunctionDistancePass());
    }
    MPM.addPass(AFLGoDistanceInstrumentationPass());
  }

  if (ClIDFuzz) MPM.addPass(IDFuzzInstrumentationPass(ClIDFuzzManifest));

  if (!ClSelectFuzz) {
    SanitizerCoverageOptions Options;
    Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;
    Options.TracePCGuard = true;
    Options.TraceCmp = true;
    MPM.addPass(ModuleSanitizerCoveragePass(Options));
  }

  MPM.addPass(AFLGoTargetInjectionFixupPass());
}

llvm::PassPluginLibraryInfo getAFLGoLinkerPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "AFLGoLinker", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerAnalysisRegistrationCallback(
            [](FunctionAnalysisManager &FAM) {
              FAM.registerPass([] { return AFLGoTargetDetectionAnalysis(); });
            });
        PB.registerAnalysisRegistrationCallback([](ModuleAnalysisManager &MAM) {
          MAM.registerPass([] {
            return DAFLAnalysis(ClDAFLInputFile, ClDAFLNoTargetsNoError,
                                ClDAFLDebug, ClDAFLVerbose);
          });
          MAM.registerPass([] { return ExtendedCallGraphAnalysis(); });
          MAM.registerPass([] { return SelectFuzzAnalysis(ClExtendCG); });
          MAM.registerPass([] { return IDFuzzAnalysis(); });
          MAM.registerPass([] {
            return AFLGoFunctionDistanceAnalysis(ClExtendCG, ClHawkeyeDistance);
          });
          MAM.registerPass(
              [] { return AFLGoBasicBlockDistanceAnalysis(ClExtendCG); });
        });

        PB.registerFullLinkTimeOptimizationLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) { addPasses(MPM); });

        PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "instrument-linker-aflgo") {
                addPasses(MPM);
                return true;
              }

              return false;
            });
      }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getAFLGoLinkerPluginInfo();
}
