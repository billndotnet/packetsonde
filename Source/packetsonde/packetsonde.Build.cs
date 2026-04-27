using UnrealBuildTool;

public class packetsonde : ModuleRules
{
    public packetsonde(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PrivateIncludePaths.Add("packetsonde");
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "Json", "JsonUtilities", "HTTP"
        });
        PrivateDependencyModuleNames.AddRange(new string[] {
            "Slate", "SlateCore"
        });
    }
}
