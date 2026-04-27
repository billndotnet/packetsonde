using UnrealBuildTool;

public class packetsondeTarget : TargetRules
{
    public packetsondeTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Game;
        DefaultBuildSettings = BuildSettingsVersion.V5;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        ExtraModuleNames.AddRange(new string[] {
            "packetsonde", "packetsondeAdapters", "packetsondeViz", "packetsondeUI"
        });
    }
}
