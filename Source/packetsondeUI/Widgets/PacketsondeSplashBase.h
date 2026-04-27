#pragma once
#include "CoreMinimal.h"
#include "Blueprint/UserWidget.h"
#include "PacketsondeSplashBase.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE(FOnSplashCompleteDelegate);

/** Abstract base for the splash widget. BP subclass WBP_Splash drives
 *  the visual sequence and calls NotifySplashComplete when done. */
UCLASS(Abstract, Blueprintable)
class PACKETSONDEUI_API UPacketsondeSplashBase : public UUserWidget
{
    GENERATED_BODY()
public:
    UFUNCTION(BlueprintImplementableEvent)
    void OnConnectionEstablished();

    UFUNCTION(BlueprintImplementableEvent)
    void OnConnectionFailed(const FString& Reason);

    UFUNCTION(BlueprintCallable)
    void NotifySplashComplete();

    UPROPERTY(BlueprintAssignable)
    FOnSplashCompleteDelegate OnSplashComplete;
};
