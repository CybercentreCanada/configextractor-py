rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { 50 45 00 00 }
    condition:
        $my_text_string or $my_hex_string
}
