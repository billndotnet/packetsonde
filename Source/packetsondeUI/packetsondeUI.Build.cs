using UnrealBuildTool;

public class packetsondeUI : ModuleRules
{
    public packetsondeUI(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PrivateIncludePaths.Add("packetsondeUI");
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "packetsonde",
            "UMG", "Slate", "SlateCore", "CommonUI", "EnhancedInput"
        });
    }
}
