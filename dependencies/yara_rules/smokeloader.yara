rule SmokeLoader
{
    meta:
        author = "kev"
        description = "SmokeLoader C2 decryption function"
        cape_type = "SmokeLoader Payload"
    strings:
        $decrypt64_1 = {44 0F B6 CF 48 8B D0 49 03 D9 4C 2B D8 8B 4B 01 41 8A 04 13 41 BA 04 00 00 00 0F C9 32 C1 C1 F9 08 49 FF CA 75 F6 F6 D0 88 02 48 FF C2 49 FF C9 75 DB 49 8B C0 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $decrypt64_2 = {40 84 FF 90 90 E8 00 00 00 00 5E 48 83 C6 1C 49 8B F8 A4 80 3E 00 75 FA 80 07 00 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $decrypt32_1 = {03 EE 8B D7 2B C7 8B F8 8B 4D 01 8A 04 17 6A 04 0F C9 5B 32 C1 C1 F9 08 4B 75 F8 F6 D0 88 02 42 4E 75 E5 8B 7C 24 14 8B C7 5F 5E 5D 5B 59 59 C3}
        $ref64_1 = {40 53 48 83 EC 20 8B 05 ?? ?? ?? ?? 83 F8 ?? 75 27 33 C0 89 05 ?? ?? ?? ?? 84 C9 74 1B BB E8 03 00 00 B9 58 02 00 00 FF 15 ?? ?? ?? ?? 48 FF CB 75 F0 8B 05 ?? ?? ?? ?? 48 63 C8 48 8D 05}
        $ref64_2 = {8B 05 ?? ?? ?? ?? 33 C9 83 F8 04 0F 44 C1 48 63 C8 89 05 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 8B 0C C8 E9}
        $ref32_1 = {8A C1 8B 0D 70 6D 00 10 83 F9 02 75 27 33 C9 89 0D 70 6D 00 10 84 C0 74 1B 56 BE E8 03 00 00 68 58 02 00 00 FF 15 38 6E 00 10 4E 75 F2 8B 0D 70 6D 00 10 5E 8B 0C 8D}
    condition:
        (any of ($decrypt*)) and (any of ($ref*))
}
