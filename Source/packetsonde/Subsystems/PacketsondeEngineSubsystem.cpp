#include "PacketsondeEngineSubsystem.h"
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
