#include "PacketsondeWorldSubsystem.h"
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
    UE_LOG(LogPacketsonde, Log, TEXT("Mode -> %s"),
        NewMode == EPacketsondeMode::Territory ? TEXT("Territory") : TEXT("Hop"));
}
