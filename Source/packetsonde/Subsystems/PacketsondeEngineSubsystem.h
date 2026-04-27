#pragma once
#include "CoreMinimal.h"
#include "Subsystems/EngineSubsystem.h"
#include "PacketsondeEngineSubsystem.generated.h"

UCLASS(BlueprintType)
class PACKETSONDE_API UPacketsondeEngineSubsystem : public UEngineSubsystem
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
