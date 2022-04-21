rule jester_stealer 
{ 
  meta: 
    description = "Rule for Jester Stealer and Lilith Botnet"
  strings: 
     $1 = {000511????12????0E0812????12????} 
     $BSJB = {42534A42} 
     $GUID = {2347554944} 
  condition: 
     all of them and uint16(0) == 0x5A4D 
 }
