# Duplicate Case Statement Fix

## Issue
Compilation error: "case value already used" for values 160-164

## Root Cause
The network tunnel command cases were added twice in the `handleClient` function:
- First occurrence: lines 1625-1643
- Duplicate occurrence: lines 1671-1689

The duplicate entries were:
- `case CMD_TOR_CONNECT:` (value 160/0xA0)
- `case CMD_TOR_API_CALL:` (value 161/0xA1) 
- `case CMD_REVERSE_SSH:` (value 162/0xA2)
- `case CMD_NETCAT_TUNNEL:` (value 163/0xA3)
- `case CMD_SOCAT_RELAY:` (value 164/0xA4)

## Fix Applied
Removed the duplicate case statements from lines 1671-1689, keeping only the first occurrence at lines 1625-1643.

## Result
The switch statement now has unique case values and should compile successfully.
