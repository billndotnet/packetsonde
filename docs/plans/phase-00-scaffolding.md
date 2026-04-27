# Phase 0 — UE5 Project Scaffolding

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A launchable UE5 project with the four modules wired up, the standard plugins enabled, the world subsystem skeleton in place, and a working splash screen that transitions into an empty world.

**Architecture:** Stock UE5.7 C++ project (`Games > Blank` template), four C++ modules (`packetsonde` core, `packetsondeAdapters`, `packetsondeViz`, `packetsondeUI`), Common UI / Enhanced Input / GameplayTags / Niagara / Geometry Script plugins enabled. Three subsystems: `UPacketsondeEngineSubsystem` (process-wide singletons), `UPacketsondeGameInstanceSubsystem` (datastore + agent connections), `UPacketsondeWorldSubsystem` (BP-callable API surface). All subsystems start as empty stubs that the next phase fills.

**Reference:** Whitepaper §5.2 (editor module structure), §10 (C++/BP boundary), §11 (third-party wheels), §12 (splash), §16.8 (subsystem layout), §23 (project layout).

**Pre-flight checks:**

- [ ] **UE5.7 installed.** Either via Epic Games Launcher or a from-source build. Verify by running `"/Users/Shared/Epic Games/UE_5.7/Engine/Binaries/Mac/UnrealEditor.app/Contents/MacOS/UnrealEditor" -version` (path varies on Linux/Windows).
- [ ] **CMake + libpcap available** for agent build (already needed; verify the existing agent builds: `cd ~/packetsonde/agent && cmake -B build && cmake --build build`).
- [ ] **Redis 7+ running** on `127.0.0.1:6379` (we don't use it in Phase 0 but next phases will).

**End state of Phase 0:**

1. The user double-clicks `packetsonde.uproject`, the editor opens.
2. PIE (Play In Editor) starts. Splash widget appears with the sonde-falling-into-binary-water animation. After ~5 seconds (or on connection-probe completion), the splash fades out and reveals an empty world with the default camera.
3. Mode pill shows in the upper-left of the HUD reading `TERRITORY (empty)`.
4. Pressing `T` toggles the pill to `HOP (empty)`.
5. Nothing else works yet — but the bones are in place.

**Lessons baked in:**

- **Subsystems first, actors second.** Subsystems give the BP authoring layer something to call from day one. Don't write any actor before the subsystem stub is in place.
- **Splash is a UMG widget driven by a BP timeline.** No engine startup-screen plugins. The whitepaper specifies fully BP-authored splash; we follow.
- **Module dependencies declared minimally.** Each module declares only the dependencies it actually uses. Avoid cyclic dependencies between `packetsonde` (core) and any of the others.
- **Use C++ for the subsystem class declarations only; defer implementation to BP-overridable hooks where reasonable.** Make the subsystem extendable by subclassing in BP for prototyping.

---

## Task 1 — Pre-flight verification

- [ ] **Confirm UE5.7 path.**

Run:

```bash
ls -d "/Users/Shared/Epic Games/UE_5.7" 2>/dev/null \
  || ls -d "/Applications/Epic Games/UE_5.7" 2>/dev/null \
  || echo "UE_5.7 not found in standard locations"
```

If not found, the user installs UE5.7 from Epic Games Launcher and re-runs.

- [ ] **Confirm agent still builds from the new repo.**

```bash
cd ~/packetsonde/agent
cmake -B build && cmake --build build -j8 2>&1 | tail -10
```

Expected: clean build. If not, the rsync from the prior project missed something — investigate.

- [ ] **Verify Redis present.**

```bash
redis-cli ping
```

Expected: `PONG`. If not, install Redis 7+ before continuing.

---

## Task 2 — Generate `packetsonde.uproject`

- [ ] **Step 1: Write the uproject file.**

Create `~/packetsonde/packetsonde.uproject`:

```json
{
    "FileVersion": 3,
    "EngineAssociation": "5.7",
    "Category": "",
    "Description": "packetsonde — a navigable spatial view of your Internet",
    "Modules": [
        {
            "Name": "packetsonde",
            "Type": "Runtime",
            "LoadingPhase": "Default",
            "AdditionalDependencies": [
                "Engine",
                "CoreUObject",
                "GameplayTags"
            ]
        },
        {
            "Name": "packetsondeAdapters",
            "Type": "Runtime",
            "LoadingPhase": "Default"
        },
        {
            "Name": "packetsondeViz",
            "Type": "Runtime",
            "LoadingPhase": "Default"
        },
        {
            "Name": "packetsondeUI",
            "Type": "Runtime",
            "LoadingPhase": "Default"
        }
    ],
    "Plugins": [
        { "Name": "EnhancedInput", "Enabled": true },
        { "Name": "CommonUI", "Enabled": true },
        { "Name": "GameplayTagsEditor", "Enabled": true },
        { "Name": "Niagara", "Enabled": true },
        { "Name": "GeometryScripting", "Enabled": true },
        { "Name": "ModelingToolsEditorMode", "Enabled": true }
    ],
    "TargetPlatforms": [ "Mac" ]
}
```

- [ ] **Step 2: Commit.**

```bash
cd ~/packetsonde
git add packetsonde.uproject
git commit -m "feat(scaffold): packetsonde.uproject with four modules + standard plugins"
```

---

## Task 3 — Module skeletons

Four modules: `packetsonde` (core), `packetsondeAdapters`, `packetsondeViz`, `packetsondeUI`. Each gets:
- `Source/<module>/<Module>.Build.cs`
- `Source/<module>/<Module>.h` and `.cpp` (the module entry point)

- [ ] **Step 1: Core module `packetsonde`.**

`Source/packetsonde/packetsonde.Build.cs`:

```csharp
using UnrealBuildTool;

public class packetsonde : ModuleRules
{
    public packetsonde(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "Json", "JsonUtilities", "HTTP"
        });
        PrivateDependencyModuleNames.AddRange(new string[] {
            "Slate", "SlateCore"
        });
    }
}
```

`Source/packetsonde/packetsonde.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"

class FPacketsondeModule : public IModuleInterface {};

DECLARE_LOG_CATEGORY_EXTERN(LogPacketsonde, Log, All);
```

`Source/packetsonde/packetsonde.cpp`:

```cpp
#include "packetsonde.h"

DEFINE_LOG_CATEGORY(LogPacketsonde);

IMPLEMENT_PRIMARY_GAME_MODULE(FPacketsondeModule, packetsonde, "packetsonde");
```

- [ ] **Step 2: Adapters module.**

`Source/packetsondeAdapters/packetsondeAdapters.Build.cs`:

```csharp
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
```

`Source/packetsondeAdapters/packetsondeAdapters.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"

class FPacketsondeAdaptersModule : public IModuleInterface {};
```

`Source/packetsondeAdapters/packetsondeAdapters.cpp`:

```cpp
#include "packetsondeAdapters.h"
IMPLEMENT_MODULE(FPacketsondeAdaptersModule, packetsondeAdapters);
```

- [ ] **Step 3: Viz module.**

`Source/packetsondeViz/packetsondeViz.Build.cs`:

```csharp
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
```

Plus matching `.h`/`.cpp` entry points using the same pattern as the adapters module.

- [ ] **Step 4: UI module.**

`Source/packetsondeUI/packetsondeUI.Build.cs`:

```csharp
using UnrealBuildTool;

public class packetsondeUI : ModuleRules
{
    public packetsondeUI(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core", "CoreUObject", "Engine", "GameplayTags",
            "packetsonde",
            "UMG", "Slate", "SlateCore", "CommonUI", "EnhancedInput"
        });
    }
}
```

Plus matching `.h`/`.cpp`.

- [ ] **Step 5: Target files.**

`Source/packetsonde.Target.cs`:

```csharp
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
```

`Source/packetsondeEditor.Target.cs`:

```csharp
using UnrealBuildTool;

public class packetsondeEditorTarget : TargetRules
{
    public packetsondeEditorTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Editor;
        DefaultBuildSettings = BuildSettingsVersion.V5;
        IncludeOrderVersion = EngineIncludeOrderVersion.Latest;
        ExtraModuleNames.AddRange(new string[] {
            "packetsonde", "packetsondeAdapters", "packetsondeViz", "packetsondeUI"
        });
    }
}
```

- [ ] **Step 6: Build to verify modules compile.**

```bash
"/Users/Shared/Epic Games/UE_5.7/Engine/Build/BatchFiles/Mac/Build.sh" \
    packetsondeEditor Mac Development \
    /Users/billn/packetsonde/packetsonde.uproject 2>&1 | tail -10
```

Expected: `Result: Succeeded`.

- [ ] **Step 7: Commit.**

```bash
git add Source/
git commit -m "feat(scaffold): four module skeletons (core, adapters, viz, UI) + targets"
```

---

## Task 4 — `Config/` defaults

- [ ] **Step 1: `Config/DefaultEngine.ini` minimal stub.**

```ini
[/Script/Engine.RendererSettings]
r.DefaultFeature.AntiAliasing=2
r.SkinCache.CompileShaders=true

[/Script/EngineSettings.GameMapsSettings]
GameDefaultMap=/Game/Maps/Empty
EditorStartupMap=/Game/Maps/Empty
```

- [ ] **Step 2: `Config/DefaultGame.ini` stub.**

```ini
[/Script/EngineSettings.GeneralProjectSettings]
ProjectName=packetsonde
ProjectVersion=0.1.0
CompanyName=
Description=A navigable spatial view of your Internet
```

- [ ] **Step 3: `Config/DefaultInput.ini` stub.** Minimal — Enhanced Input action mappings will be authored as `IA_*` and `IMC_*` assets in `Content/Input/` rather than INI.

```ini
[/Script/Engine.InputSettings]
DefaultPlayerInputClass=/Script/EnhancedInput.EnhancedPlayerInput
DefaultInputComponentClass=/Script/EnhancedInput.EnhancedInputComponent
```

- [ ] **Step 4: GameplayTags config.** `Config/Tags/Default.ini`:

```ini
[/Script/GameplayTags.GameplayTagsSettings]
ImportTagsFromConfig=True
WarnOnInvalidTags=True
+GameplayTagSource=DefaultGameplayTags.ini
```

`Config/DefaultGameplayTags.ini` — taxonomy from whitepaper §26.9. Skipping the full list here for brevity; the Phase 0 implementer copies the bullets from the whitepaper into this file in the GameplayTag config format:

```ini
[/Script/GameplayTags.GameplayTagsList]
+GameplayTagList=(Tag="Org.Role.Hyperscaler",DevComment="")
+GameplayTagList=(Tag="Org.Role.CDN",DevComment="")
... (and so on for the full taxonomy)
```

- [ ] **Step 5: Commit.**

```bash
git add Config/
git commit -m "feat(scaffold): Config/ defaults — engine, game, input, GameplayTags taxonomy"
```

---

## Task 5 — Subsystem skeletons

Three subsystems. All in the `packetsonde` core module.

- [ ] **Step 1: `UPacketsondeEngineSubsystem`.**

`Source/packetsonde/Subsystems/PacketsondeEngineSubsystem.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Subsystems/EngineSubsystem.h"
#include "PacketsondeEngineSubsystem.generated.h"

/** Process-wide singletons: IATA airport table, country flag cache,
 *  archetype mesh cache. Initialized once per process. Empty in Phase 0. */
UCLASS(BlueprintType)
class PACKETSONDE_API UPacketsondeEngineSubsystem : public UEngineSubsystem
{
    GENERATED_BODY()
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    /** True when init has completed and singletons are ready. */
    UFUNCTION(BlueprintCallable, BlueprintPure)
    bool IsReady() const { return bReady; }

private:
    bool bReady = false;
};
```

`.cpp`:

```cpp
#include "Subsystems/PacketsondeEngineSubsystem.h"
#include "packetsonde.h"

void UPacketsondeEngineSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    UE_LOG(LogPacketsonde, Log, TEXT("PacketsondeEngineSubsystem initialized"));
    bReady = true;
}

void UPacketsondeEngineSubsystem::Deinitialize()
{
    bReady = false;
    Super::Deinitialize();
}
```

- [ ] **Step 2: `UPacketsondeGameInstanceSubsystem`.**

`Source/packetsonde/Subsystems/PacketsondeGameInstanceSubsystem.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "PacketsondeGameInstanceSubsystem.generated.h"

/** Per-game-instance state: datastore, agent connections, persistent UI
 *  preferences. Empty in Phase 0; Phase 1 attaches the datastore. */
UCLASS(BlueprintType)
class PACKETSONDE_API UPacketsondeGameInstanceSubsystem : public UGameInstanceSubsystem
{
    GENERATED_BODY()
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    bool IsReady() const { return bReady; }

private:
    bool bReady = false;
};
```

`.cpp`: equivalent stub.

- [ ] **Step 3: `UPacketsondeWorldSubsystem`.**

`Source/packetsonde/Subsystems/PacketsondeWorldSubsystem.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Subsystems/WorldSubsystem.h"
#include "PacketsondeWorldSubsystem.generated.h"

UENUM(BlueprintType)
enum class EPacketsondeMode : uint8
{
    Territory,
    Hop
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnPacketsondeModeChanged, EPacketsondeMode, NewMode);

/** Per-world BP-callable API surface. The only way Blueprints touch the
 *  data layer. Empty in Phase 0 except the mode toggle. */
UCLASS(BlueprintType)
class PACKETSONDE_API UPacketsondeWorldSubsystem : public UWorldSubsystem
{
    GENERATED_BODY()
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, BlueprintPure)
    EPacketsondeMode GetMode() const { return CurrentMode; }

    UFUNCTION(BlueprintCallable)
    void SetMode(EPacketsondeMode NewMode);

    UPROPERTY(BlueprintAssignable)
    FOnPacketsondeModeChanged OnModeChanged;

private:
    EPacketsondeMode CurrentMode = EPacketsondeMode::Territory;
};
```

`.cpp`:

```cpp
#include "Subsystems/PacketsondeWorldSubsystem.h"
#include "packetsonde.h"

void UPacketsondeWorldSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    UE_LOG(LogPacketsonde, Log, TEXT("PacketsondeWorldSubsystem initialized in mode Territory"));
}

void UPacketsondeWorldSubsystem::Deinitialize() { Super::Deinitialize(); }

void UPacketsondeWorldSubsystem::SetMode(EPacketsondeMode NewMode)
{
    if (NewMode == CurrentMode) return;
    CurrentMode = NewMode;
    OnModeChanged.Broadcast(NewMode);
    UE_LOG(LogPacketsonde, Log, TEXT("Mode → %s"),
        NewMode == EPacketsondeMode::Territory ? TEXT("Territory") : TEXT("Hop"));
}
```

- [ ] **Step 4: Build, commit.**

```bash
"/Users/Shared/Epic Games/UE_5.7/Engine/Build/BatchFiles/Mac/Build.sh" \
    packetsondeEditor Mac Development \
    /Users/billn/packetsonde/packetsonde.uproject 2>&1 | tail -5

git add Source/packetsonde/Subsystems/
git commit -m "feat(scaffold): three subsystem skeletons (Engine / GameInstance / World)"
```

---

## Task 6 — Empty world map

- [ ] **Step 1: Open the editor.** First-launch generates derived data and may take several minutes. Once open, the editor presents an empty default map.

- [ ] **Step 2: Save an empty level.** File → New Level → Empty Level. Save As `/Game/Maps/Empty`.

- [ ] **Step 3: Configure default + startup map.** Edit → Project Settings → Maps & Modes. Set Editor Startup Map and Game Default Map to `/Game/Maps/Empty`.

- [ ] **Step 4: Add a default `PlayerStart`** at the world origin. Save.

- [ ] **Step 5: Commit.**

```bash
git add Content/Maps/
git commit -m "feat(scaffold): empty default map at /Game/Maps/Empty with PlayerStart"
```

---

## Task 7 — Splash widget shell

- [ ] **Step 1: Create the C++ base class.**

`Source/packetsondeUI/Widgets/PacketsondeSplashBase.h`:

```cpp
#pragma once
#include "CoreMinimal.h"
#include "Blueprint/UserWidget.h"
#include "PacketsondeSplashBase.generated.h"

UCLASS(Abstract, Blueprintable)
class PACKETSONDEUI_API UPacketsondeSplashBase : public UUserWidget
{
    GENERATED_BODY()
public:
    /** Triggered by the (eventual) Phase 1 connection probe. BP completes the
     *  splash and transitions to the world view. Phase 0: just call this from
     *  a BP timer after ~5 seconds. */
    UFUNCTION(BlueprintImplementableEvent)
    void OnConnectionEstablished();

    UFUNCTION(BlueprintImplementableEvent)
    void OnConnectionFailed(const FString& Reason);

    /** Called by BP when the splash sequence completes; the GameMode swaps
     *  to the world view widget. */
    UFUNCTION(BlueprintCallable)
    void NotifySplashComplete();

    UPROPERTY(BlueprintAssignable)
    FOnSplashCompleteDelegate OnSplashComplete;
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE(FOnSplashCompleteDelegate);
```

`.cpp`:

```cpp
#include "Widgets/PacketsondeSplashBase.h"

void UPacketsondeSplashBase::NotifySplashComplete()
{
    OnSplashComplete.Broadcast();
}
```

- [ ] **Step 2: Create the BP subclass `WBP_Splash`.** In editor: Right-click in `/Game/UI/Splash/`, `User Widget`, parent class `PacketsondeSplashBase`. Open it.

- [ ] **Step 3: Author the splash sequence.**

Minimum Phase 0 splash (we'll polish in Phase 5+):

- Black background.
- Centered `packetsonde` text in monospace, opacity 0 → 1 over 1.5s.
- A 5-second BP timer that calls `NotifySplashComplete`.

The full bobber-on-binary-water sequence (whitepaper §12) lands later. Phase 0 just gets the wire.

- [ ] **Step 4: Game mode that shows the splash on `BeginPlay`.**

`Source/packetsondeUI/PacketsondeGameMode.h` and `.cpp` — a thin `AGameModeBase` subclass that on `BeginPlay` creates `WBP_Splash`, adds it to viewport, listens for `OnSplashComplete`, then on completion creates the (empty for now) `WBP_World` widget.

- [ ] **Step 5: Set the GameMode in the world settings of `/Game/Maps/Empty`.**

- [ ] **Step 6: PIE test.** Click Play. Splash appears, fades, dismisses. Empty world remains.

- [ ] **Step 7: Commit.**

```bash
git add Source/packetsondeUI/ Content/UI/Splash/ Content/Maps/Empty.umap
git commit -m "feat(scaffold): splash widget shell + GameMode that drives it"
```

---

## Task 8 — Mode pill HUD shell

- [ ] **Step 1: Create `WBP_ModePill`** under `/Game/UI/HUD/`. Parent: `UserWidget` (or a small C++ base if needed). Layout: a small floating pill (text + background) anchored upper-left.

- [ ] **Step 2: Bind the text** to a function that reads `UPacketsondeWorldSubsystem::GetMode()` and renders `TERRITORY (empty)` or `HOP (empty)`.

- [ ] **Step 3: Listen to `OnModeChanged`** and refresh on broadcast.

- [ ] **Step 4: Add mode-pill to `WBP_World`** so it's visible after the splash.

- [ ] **Step 5: Enhanced Input — `T` key toggles mode.**

  - Create `IA_ToggleMode` (Enhanced Input Action) at `/Game/Input/`.
  - Create `IMC_Default` (Input Mapping Context) at `/Game/Input/`.
  - Bind `T` → `IA_ToggleMode`.
  - Add the mapping context in `WBP_World::Construct` via the `EnhancedInputLocalPlayerSubsystem`.
  - On `IA_ToggleMode` triggered, call `WorldSubsystem->SetMode(...)` flipping between Territory and Hop.

- [ ] **Step 6: PIE test.**

  - Splash appears, dismisses.
  - Mode pill shows `TERRITORY (empty)`.
  - Press T → pill switches to `HOP (empty)`.
  - Press T again → back to `TERRITORY (empty)`.
  - The output log shows `LogPacketsonde: Mode → Hop` / `Mode → Territory`.

- [ ] **Step 7: Commit.**

```bash
git add Source/ Content/UI/HUD/ Content/Input/
git commit -m "feat(scaffold): mode pill HUD + Enhanced Input T-toggle bound to WorldSubsystem.SetMode"
```

---

## Task 9 — Tag the milestone

- [ ] **Final verification.**

Re-launch the editor cold. PIE. Splash. Empty world. Mode pill toggles via T. No errors in log.

- [ ] **Tag.**

```bash
cd ~/packetsonde
git tag -a phase-0-complete -m "Phase 0 — UE5 scaffolding complete

- packetsonde.uproject + four module skeletons + plugin imports
- Three subsystems (Engine, GameInstance, World) skeletons in C++
- Empty default map
- Splash widget shell driven by GameMode
- Mode pill HUD reading WorldSubsystem.GetMode
- Enhanced Input T-toggle wired to WorldSubsystem.SetMode

Next: Phase 1 — local agent connectivity."
```

---

## Self-Review Notes

**Spec coverage:** Whitepaper §5.2 (modules), §10 (C++/BP boundary), §11 (plugins), §12 (splash), §16.8 (subsystems), §23 (project layout) all touched. Splash content per §12 is intentionally minimal in Phase 0 — full bobber-on-binary-water sequence is deferred.

**Known deferrals:**
- `Config/DefaultGameplayTags.ini` ships with the full taxonomy from §26.9 — actual content copied during Task 4.
- Splash visuals are placeholder until Phase 5+.
- The `UPacketsondeWorldSubsystem` API surface in §16.9 of the whitepaper is much larger than what Phase 0 implements; we add methods as the phases that need them land.

**Pre-flight that engineer must verify before starting:**
1. UE5.7 actually installed and findable.
2. The agent in `~/packetsonde/agent/` builds cleanly from a fresh checkout.
3. Redis is up.

If any of these fail, Phase 0 is blocked until resolved.
