rule test
{
	meta:
		author = "Finch"
	strings:
		$1 = {83 F8 78 0F 85 ?? 01 00 00 6A 05 59 31 D2 42 E8 ?? ?? ?? 00 8? C?}
	condition:
		$1 and uint16(0) == 0x5A4D
}
