#include "PacketsondeGameInstanceSubsystem.h"
#include "packetsonde.h"

void UPacketsondeGameInstanceSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    UE_LOG(LogPacketsonde, Log, TEXT("PacketsondeGameInstanceSubsystem initialized"));
    bReady = true;
}

void UPacketsondeGameInstanceSubsystem::Deinitialize()
{
    bReady = false;
    Super::Deinitialize();
}
