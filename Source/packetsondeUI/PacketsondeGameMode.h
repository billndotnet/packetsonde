#pragma once
#include "CoreMinimal.h"
#include "GameFramework/GameModeBase.h"
#include "PacketsondeGameMode.generated.h"

class UPacketsondeSplashBase;
class UUserWidget;

/** GameMode that spawns the splash widget on BeginPlay, waits for its
 *  completion, then swaps to the world view widget. BP subclass sets the
 *  splash + world widget classes. */
UCLASS(Blueprintable)
class PACKETSONDEUI_API APacketsondeGameMode : public AGameModeBase
{
    GENERATED_BODY()
public:
    APacketsondeGameMode();

    virtual void BeginPlay() override;

protected:
    UPROPERTY(EditDefaultsOnly, BlueprintReadOnly, Category = "packetsonde|UI")
    TSubclassOf<UPacketsondeSplashBase> SplashWidgetClass;

    UPROPERTY(EditDefaultsOnly, BlueprintReadOnly, Category = "packetsonde|UI")
    TSubclassOf<UUserWidget> WorldWidgetClass;

    UFUNCTION()
    void HandleSplashComplete();

private:
    UPROPERTY()
    TObjectPtr<UPacketsondeSplashBase> ActiveSplash;

    UPROPERTY()
    TObjectPtr<UUserWidget> ActiveWorldWidget;
};
