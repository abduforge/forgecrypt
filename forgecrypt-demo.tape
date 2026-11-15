Output docs/assets/forgecrypt-demo.gif

Require forgecrypt
Require cmp

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 620
Set TypingSpeed 40ms

Hide
Type "mkdir -p /tmp/forgecrypt-demo"
Enter
Type "cd /tmp/forgecrypt-demo"
Enter
Type "printf 'ForgeCrypt 2.0 GLOBAL demo' > demo.txt"
Enter
Show

Type "forgecrypt --version"
Enter
Sleep 1s

Type "forgecrypt encrypt demo.txt demo.txt.fgc"
Enter
Sleep 500ms
Hide
Type "demo-only-passphrase"
Enter
Type "demo-only-passphrase"
Enter
Show
Sleep 1s

Type "forgecrypt verify demo.txt.fgc"
Enter
Sleep 500ms
Hide
Type "demo-only-passphrase"
Enter
Show
Sleep 1s

Type "forgecrypt decrypt demo.txt.fgc restored.txt"
Enter
Sleep 500ms
Hide
Type "demo-only-passphrase"
Enter
Show
Sleep 1s

Type "cmp demo.txt restored.txt && echo 'ROUND-TRIP OK'"
Enter
Sleep 3s
