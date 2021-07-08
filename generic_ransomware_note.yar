rule generic_ransomware_note
{     
   strings:     
      $ = "What happened to my files" ascii wide     
      $ = "Your files have been encrypted" ascii wide
      $ = "All your data is encrypted" ascii wide
      $ = "All your important files are encrypted" ascii wide	     
      $ = "Do not rename" ascii wide
      $ = "Do not try" ascii wide
      $ = "third party software" ascii wide
      $ = "antivirus solutions" ascii wide
      $ = "TOR browser" ascii wide
      $ = "https://torproject.org/" ascii wide
      $ = "TOR blocked" ascii wide      
      $ = "using military" ascii wide     
      $ = "after paying the ransom"  
      $ = "If you want to restore them" ascii wide 
      $ = "After payment we will send you" ascii wide 
      $ = "DECRYPT.txt" ascii wide 
      $ = "it may cause permanent data loss" ascii wide 
      $ = "You can buy bitcoins from the following sites" ascii wide
      $ = "buy bitcoins" ascii wide     
      $ = "If you won't pay after" ascii wide 
      $ = "https://www.coindesk.com/information/how-can-i-buy-bitcoins" ascii wide  
      $ = "Decrypt.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "Decrypt-Files.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "DECRYPT-FILES.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT_INSTRUCTION.TXT" ascii wide 
      $ = "FILES ENCRYPTED.txt" ascii wide
      $ = "DECRYPT MY FILES" ascii wide 
      $ = "DECRYPT-MY-FILES" ascii wide 
      $ = "DECRYPT_MY_FILES" ascii wide
      $ = "DECRYPT YOUR FILES" ascii wide  
      $ = "DECRYPT-YOUR-FILES" ascii wide 
      $ = "DECRYPT_YOUR_FILES" ascii wide 
      $ = "DECRYPT FILES.txt" ascii wide
      $ = "How To Decrypt Files" ascii wide
      $ = "What's wrong with my files?" ascii wide
      $ = "Your computer's important files have been encrypted" ascii wide
      $ = "You have to pay" ascii wide
      $ = "After payment" ascii wide
      $ = "it may cause permanent data loss" ascii wide
      $ = "pay for decryption key" ascii wide
      $ = "You need to buy decryptor" ascii wide
      $ = "Your files have been encrypted by" ascii wide
      $ = "encrypted by" ascii wide
      $ = "get the decryption password" ascii wide
      $ = "Downloads\\README.txt" ascii wide
      $ = "Music\\README.txt" ascii wide
      $ = "Videos\\README.txt" ascii wide
      $ = "Pictures\\README.txt" ascii wide
      $ = "Desktop\\README.txt" ascii wide
      $ = "Documents\\README.txt" ascii wide
      $ = "We will send key to your email" ascii wide
      $ = "All your file has been locked" ascii wide
      $ = "a victim of a scam" ascii wide
      $ = "a victim of a fraud" ascii wide
      $ = "to restore your files" ascii wide
      $ = "get your files back" ascii wide
      $ = "Your personal ID" ascii wide
      $ = "vssadmin delete shadows" ascii wide
      $ = ".onion" ascii wide
      $ = "valuable information" ascii wide 	
      $ = /(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[A-Za-z0-9-]*[A-Za-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/
      $ = /(?:https?:\/\/)?(?:www)?(\S*?\.onion)\b/		  			  
  condition:     
      uint16(0) == 0x5a4d and 2 of them 
}
