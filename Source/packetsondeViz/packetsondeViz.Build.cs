using UnrealBuildTool;

public class packetsondeViz : ModuleRules
{
    public packetsondeViz(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "packetsonde",
            "ProceduralMeshComponent", "GeometryScriptingCore", "Niagara"
        });
    }
}
