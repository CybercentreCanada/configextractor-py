rule RedLeaf
{
    meta:
        author = "kev"
        description = "RedLeaf configuration parser."
        cape_type = "RedLeaf Payload"
    strings:
        $crypto = {6A 10 B8 ?? ?? ?? 10 E8 ?? ?? 01 00 8B F1 89 75 E4 8B 7D 08 83 CF 07 81 FF FE FF FF 7F 76 05 8B 7D 08 EB 29 8B 4E 14 89 4D EC D1 6D EC 8B C7 33 D2 6A 03 5B F7 F3 8B 55 EC 3B D0 76 10 BF FE FF FF}
        $decrypt_config = {55 8B EC 83 EC 20 A1 98 9F 03 10 33 C5 89 45 FC 56 33 F6 33 C0 80 B0 ?? ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 72 F1 68 70 99 03 10 56 56 FF 15 2C 11 03 10 FF 15 B8 11 03 10 3D B7 00 00 00 75 06 56 E8 5F 9E}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $crypto and $decrypt_config
}
