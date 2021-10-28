rule EmotetInmemory
{
    meta:
        id = "3i5A6TXf4YHLSnKsCC6mPn"
        fingerprint = "fd0d6b3cb388c6c635a12fa6255ce05d57134fca6bef5debe5ff2f0def7682b0"
        version = "1.0"
        first_imported = "2020-09-23"
        last_modified = "2020-09-23"
        status = "RELEASED"
        sharing = "TLP:AMBER"
        source = "CCCS"
        author = "reveng@CCCS"
        description = "Find unpack Emotet within a process"
        category = "MALWARE"
        malware = "EMOTET"
        malware_type = "BANKER"
        mitre_att = "S0266"
        report = "TA20-0369"
        vol_script = "malware/Crimeware/Heodo/EmotetExtract_malduck.py"
    strings:
        $populC2_1 = /\x33\xc0\xc7\x05[\S\s]{4}[\S\s]{4}\xc7\x05[\S\s]{8}\xa3[\S\s]{4}\xa3[\S\s]{4}\xa3/
        $populC2_2 = /\xB8[\S\s]{4}\xA3.{4}\xA3.{4}\x33\xC0/
        $populC2_3 = /\xE8.{4}\xA3.{4}\x85.{1,5}\xB9[\S\s]{4}\x33/
        $populC2_4 = /\xE8.{4}\xA3.{4}\x6A.\x6A.{0,20}\xC7\x40.[\S\s]{4}\xC7/
        $rsa = /\x6A\x00\x6A\x01\xFF\x76.{1,30}\xB9[\S\s]{4}.{0,10}\xE8/
    condition:
        uint16(0) == 0x5A4D and any of ($populC2*) and $rsa
}
