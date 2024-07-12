import type { TurboModule } from "react-native/Libraries/TurboModule/RCTExport";
import { TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
    DKLsDkgPhase1(data: string): Promise<string>;
    DKLsDkgPhase2(data: string): Promise<string>;
    DKLsDkgPhase3(data: string): Promise<string>;
    DKLsDkgPhase4(data: string): Promise<string>;

    DKLsSignPhase1(data: string): Promise<string>;
    DKLsSignPhase2(data: string): Promise<string>;
    DKLsSignPhase3(data: string): Promise<string>;
    DKLsSignPhase4(data: string): Promise<string>;

    DKLsVerifyECDSASignature(data: string): Promise<string>;

    DKLsDerivation(data: string): Promise<string>;

    DKLsReKey(data: string): Promise<string>;
}

export default TurboModuleRegistry.get<Spec>("ZeroxTSS") as Spec | null;
