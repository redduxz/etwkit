#pragma once

#include <evntcons.h>
#include <string>
#include "enrich.h"

void ConsoleRenderInit();
void ConsoleRender(PEVENT_RECORD rec, ProcCache& cache);
