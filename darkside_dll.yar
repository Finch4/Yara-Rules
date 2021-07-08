rule darkside_dll 
{
  meta:
    	  author = "Finch"
    	  description = "Developed with Monk"
  strings:
	  $hex1 = {1E5C754766837C1E045C753F66837C1E}
	  $hex2 = {10FF75F?FF15B0080110??4???0?000?}

  condition:
	  all of them and uint16(0) == 0x5a4d and filesize >= 40KB and filesize <= 80KB
}
