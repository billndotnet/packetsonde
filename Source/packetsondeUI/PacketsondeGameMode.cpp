#include "PacketsondeGameMode.h"
#include "Widgets/PacketsondeSplashBase.h"
#include "Blueprint/UserWidget.h"
#include "Kismet/GameplayStatics.h"

APacketsondeGameMode::APacketsondeGameMode()
{
    PrimaryActorTick.bCanEverTick = false;
}

void APacketsondeGameMode::BeginPlay()
{
    Super::BeginPlay();

    if (!SplashWidgetClass)
    {
        return;
    }

    APlayerController* PC = UGameplayStatics::GetPlayerController(this, 0);
    if (!PC)
    {
        return;
    }

    ActiveSplash = CreateWidget<UPacketsondeSplashBase>(PC, SplashWidgetClass);
    if (ActiveSplash)
    {
        ActiveSplash->OnSplashComplete.AddDynamic(this, &APacketsondeGameMode::HandleSplashComplete);
        ActiveSplash->AddToViewport(100);
    }
}

void APacketsondeGameMode::HandleSplashComplete()
{
    if (ActiveSplash)
    {
        ActiveSplash->RemoveFromParent();
        ActiveSplash = nullptr;
    }

    if (!WorldWidgetClass)
    {
        return;
    }

    APlayerController* PC = UGameplayStatics::GetPlayerController(this, 0);
    if (!PC)
    {
        return;
    }

    ActiveWorldWidget = CreateWidget<UUserWidget>(PC, WorldWidgetClass);
    if (ActiveWorldWidget)
    {
        ActiveWorldWidget->AddToViewport(0);
    }
}
