#pragma once
#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "PacketsondeGameInstanceSubsystem.generated.h"

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
