#include "Widgets/PacketsondeSplashBase.h"

void UPacketsondeSplashBase::NotifySplashComplete()
{
    OnSplashComplete.Broadcast();
}
