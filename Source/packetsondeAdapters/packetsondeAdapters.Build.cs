using UnrealBuildTool;

public class packetsondeAdapters : ModuleRules
{
    public packetsondeAdapters(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "packetsonde",
            "HTTP", "WebSockets", "Json", "JsonUtilities"
        });
    }
}
