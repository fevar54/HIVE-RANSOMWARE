rule hive_ransomware {
    meta:
        description = "Identifies Hive ransomware based on the presence of the .key file and HOW_TO_DECRYPT.txt ransom note"
        author = "FEVAR54"
    strings:
        $key_file = "*.key" nocase
        $ransom_note = "HOW_TO_DECRYPT.txt" nocase
        $tor_link = "*.onion" nocase
    condition:
        any of ($key_file, $ransom_note, $tor_link)
}
