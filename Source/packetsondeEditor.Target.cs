using UnrealBuildTool;

public class packetsondeEditorTarget : TargetRules
{
    public packetsondeEditorTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Editor;
        DefaultBuildSettings = BuildSettingsVersion.V6;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        bOverrideBuildEnvironment = true;
        ExtraModuleNames.AddRange(new string[] {
            "packetsonde", "packetsondeAdapters", "packetsondeViz", "packetsondeUI"
        });
    }
}
