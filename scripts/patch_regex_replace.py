import io, re
APP_PATH = r"\\\\diskstation\\web\\sitjoy\\app.py"
with io.open(APP_PATH, 'r', encoding='utf-8', errors='surrogatepass') as f:
    s = f.read()
pattern = re.compile(r"for variant in \(nfc, nfd\):[\s\S]*?(?=\n\s*def _is_image_name\()", re.M)
new_loop = '''# Add multiple byte-encoding variants for more robust matching across
        # filesystem encodings and database-stored strings. Try fs encoding first,
        # then fall back to several common encodings with surrogatepass so that
        # round-trip surrogate bytes are preserved when present on the NAS.
        for variant in (nfc, nfd):
            if not variant:
                continue
            encodings_to_try = []
            try:
                encodings_to_try.append(os.fsencode(variant))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('utf-8', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('gb18030', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('latin-1', errors='surrogatepass'))
            except Exception:
                pass

            # de-duplicate byte variants
            seen = set()
            for b in encodings_to_try:
                if not isinstance(b, (bytes, bytearray)):
                    continue
                if b in seen:
                    continue
                seen.add(b)
                try:
                    b64 = base64.b64encode(b).decode('ascii')
                    if b64 not in bound_b64_map:
                        bound_b64_map[b64] = set()
                    if fabric_id is not None:
                        bound_b64_map[b64].add(int(fabric_id))
                except Exception:
                    continue
'''
new_s, n = pattern.subn(new_loop, s, count=1)
if n:
    with io.open(APP_PATH, 'w', encoding='utf-8', errors='surrogatepass') as f:
        f.write(new_s)
    print('Replaced via regex')
else:
    print('Pattern not found')
