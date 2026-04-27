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
