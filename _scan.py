import io, re
s = io.open('index.html', encoding='utf-8').read()
pat = re.compile(r'class="[^"]*\bbg-(teal-700|teal-600|rose-600|rose-500|red-700|red-600|amber-600|emerald|indigo)[^"]*"')
for m in pat.finditer(s):
    line = s[:m.start()].count('\n') + 1
    print(line, m.group(0)[:150])
