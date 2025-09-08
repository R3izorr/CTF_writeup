# weird-app
**Category:** Reversing
**Difficulty:** 4/10
**Author:** cleverbear57

## Description
I made this weird android app, but all it gave me was this .apk file. Can you get the flag from it?

## Distribution
weird.zip


---

## Problem Statement

The APK performs a position-dependent substitution on each character of the input flag:

- **Letters** `a–z`: shift forward by `+i` (mod 26) where `i` is the character index.
- **Digits** `0–9`: shift forward by `+2*i` (mod 10).
- **Specials** `!@#$%^&*()_+{}[]|`: shift forward by `+i²` (mod 18).

The UI then displays the transformed result. We must **reverse** these shifts to recover the original flag.

---

## Tools

- **jadx-gui** (static decompilation of APK to Java/Kotlin)
- **Python 3** (to implement the decoder)

---

## Step-by-Step

### 1 Open the APK in jadx-gui
1. Launch `jadx-gui`.
2. `File` → `Open` → select `app-debug.apk`.
3. In the left tree, expand `sources` and browse `MainActivityKt`.
4. Locate the decompiled function:

'''kotlin
public static final String transformFlag(String flag) {
    String res = "";
    int length = flag.length();
    for (int i = 0; i < length; i++) {
        // letters
        for (int c = 0; c < 26; c++) {
            if ("abcdefghijklmnopqrstuvwxyz".charAt(c) == flag.charAt(i)) {
                int ind = c + i;
                res += "abcdefghijklmnopqrstuvwxyz".charAt(ind % 26);
            }
        }
        // digits
        for (int c = 0; c < 10; c++) {
            if ("0123456789".charAt(c) == flag.charAt(i)) {
                int ind2 = (i * 2) + c;
                res += "0123456789".charAt(ind2 % 10);
            }
        }
        // specials
        for (int c = 0; c < 18; c++) {
            if ("!@#$%^&*()_+{}[]|".charAt(c) == flag.charAt(i)) {
                int ind3 = (i * i) + c;
                res += "!@#$%^&*()_+{}[]|".charAt(ind3 % 18);
            }
        }
    }
    return res;
}
'''
idvi+1{s6e3{)arg2zv[moqa905+
This is the encoded form of the actual flag.

so the function decoded the flag :
Letters (a–z): shifted forward by +i positions mod 26

Digits (0–9): shifted forward by +2*i positions mod 10

Specials (!@#$%^&*()_+{}[]|): shifted forward by +i² positions mod 18

Where i = index of character in the string (0-based)

5. Inversion (Decoding Rules)

Since the transform is reversible:

Letters: orig = (encIndex – i) mod 26

Digits: orig = (encIndex – 2*i) mod 10

Specials: orig = (encIndex – i²) mod 18
'''python
abc = "abcdefghijklmnopqrstuvwxyz"
dig = "0123456789"
spec = "!@#$%^&*()_+{}[]|"

out = "idvi+1{s6e3{)arg2zv[moqa905+"
res = []

for i, ch in enumerate(out):
    if ch in abc:
        res.append(abc[(abc.index(ch) - i) % 26])
    elif ch in dig:
        res.append(dig[(dig.index(ch) - 2*i) % 10])
    elif ch in spec:
        res.append(spec[(spec.index(ch) - i*i) % len(spec)])

print("".join(res))
'''
ictf{1_l0v3_@ndr0id_stud103}




