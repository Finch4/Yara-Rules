rule gandcrab
{
 	meta:
    		author = "Finch"
	strings:
		$hex1 = { 55 8B EC 83 EC ?? 53 56 ?? 3? ?? ?? ?? ?? 5? ?? }
		$hex2 = { 8B 45 08 33 45 FC 89 ?1 ?C ?? ?? ?? ?? ?8 ?? ?? }
	condition:
		all of them and uint16(0) == 0x5A4D
}
