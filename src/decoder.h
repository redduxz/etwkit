#pragma once

#include <windows.h>
#include <evntcons.h>
#include <string>

std::wstring DecodeEventToJson(PEVENT_RECORD rec);
std::wstring GuidToString(const GUID& g);
std::wstring IsoTimestamp(const FILETIME& ft);
