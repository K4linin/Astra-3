# 🔍 Fuzzing Dashboard: `img2pdf_convert`

**Generated:** 2026-02-15 17:08:01 UTC

---

## 📊 Summary

| Metric | Value |
|--------|-------|
| **Total Crashes** | 658 |
| **Unique Types** | 4 |
| **Critical/High** | 0 |
| **Medium** | 498 |
| **Low** | 160 |

---

## 🐛 Crash Types

| Type | Count | Severity |
|------|-------|----------|
| `ZeroDivisionError` | 498 | 🟠 high |
| `SyntaxError` | 71 | 🟢 low |
| `Exception` | 49 | 🟡 medium |
| `DecompressionBombError` | 40 | 🟢 low |

---

## 🔬 Sample Crashes

### 🟡 Crash #1: `ZeroDivisionError`

- **Severity:** medium
- **Input (hex):** `ffd8ffe000104a464946003c010100000100010000ffdb0043...`

<details>
<summary>Stack Trace</summary>

```
Traceback (most recent call last):
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\scripts\fuzzing_monitor.py", line 413, in _run_single_test
    self.fuzz_function(data)
    ~~~~~~~~~~~~~~~~~~^^^^^^
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\targets\img2pdf_convert.py", line 130, in fuzz_target
    pdf_bytes = img2pdf.convert([img_stream])
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3100, in convert
    pdf = convert_to_docobject(*images, **kwargs)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3029, in convert_to_docobject
    pagewidth, pageheight, imgwidthpdf, imgheightpdf = kwargs["layout_fun"](
                                                       ~~~~~~~~~~~~~~~~~~~~^
        imgwidthpx, imgheightpx, ndpi
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2868, in default_layout_fun
    imgwidthpdf = pagewidth = px_to_pt(imgwidthpx, ndpi[0])
                              ~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2616, in px_to_pt
    return 72.0 * length / dpi
           ~~~~~~~~~~~~~~^~~~~
ZeroDivisionError: division by zero

```

</details>

---

### 🟡 Crash #2: `ZeroDivisionError`

- **Severity:** medium
- **Input (hex):** `ffd8ffe000104a4649460001170100000100010000ffdb0043...`

<details>
<summary>Stack Trace</summary>

```
Traceback (most recent call last):
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\scripts\fuzzing_monitor.py", line 413, in _run_single_test
    self.fuzz_function(data)
    ~~~~~~~~~~~~~~~~~~^^^^^^
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\targets\img2pdf_convert.py", line 130, in fuzz_target
    pdf_bytes = img2pdf.convert([img_stream])
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3100, in convert
    pdf = convert_to_docobject(*images, **kwargs)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3029, in convert_to_docobject
    pagewidth, pageheight, imgwidthpdf, imgheightpdf = kwargs["layout_fun"](
                                                       ~~~~~~~~~~~~~~~~~~~~^
        imgwidthpx, imgheightpx, ndpi
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2868, in default_layout_fun
    imgwidthpdf = pagewidth = px_to_pt(imgwidthpx, ndpi[0])
                              ~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2616, in px_to_pt
    return 72.0 * length / dpi
           ~~~~~~~~~~~~~~^~~~~
ZeroDivisionError: division by zero

```

</details>

---

### 🟢 Crash #3: `DecompressionBombError`

- **Severity:** low
- **Input (hex):** `ffd8ffe000104a46494600010100000100010000ffdb004300...`

<details>
<summary>Stack Trace</summary>

```
Traceback (most recent call last):
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\scripts\fuzzing_monitor.py", line 413, in _run_single_test
    self.fuzz_function(data)
    ~~~~~~~~~~~~~~~~~~^^^^^^
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\targets\img2pdf_convert.py", line 130, in fuzz_target
    pdf_bytes = img2pdf.convert([img_stream])
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3100, in convert
    pdf = convert_to_docobject(*images, **kwargs)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3022, in convert_to_docobject
    ) in read_images(
         ~~~~~~~~~~~^
        rawdata,
        ^^^^^^^^
    ...<3 lines>...
        kwargs["include_thumbnails"],
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ):
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2049, in read_images
    imgdata = Image.open(im)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\Image.py", line 3558, in open
    im = _open_core(fp, filename, prefix, formats)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\Image.py", line 3547, in _open_core
    _decompression_bomb_check(im.size)
    ~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\PIL\Image.py", line 3448, in _decompression_bomb_check

```

</details>

---

### 🟡 Crash #4: `ZeroDivisionError`

- **Severity:** medium
- **Input (hex):** `ffd8ffe000104a4649460001010100000100000100010000ff...`

<details>
<summary>Stack Trace</summary>

```
Traceback (most recent call last):
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\scripts\fuzzing_monitor.py", line 413, in _run_single_test
    self.fuzz_function(data)
    ~~~~~~~~~~~~~~~~~~^^^^^^
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\targets\img2pdf_convert.py", line 130, in fuzz_target
    pdf_bytes = img2pdf.convert([img_stream])
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3100, in convert
    pdf = convert_to_docobject(*images, **kwargs)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3029, in convert_to_docobject
    pagewidth, pageheight, imgwidthpdf, imgheightpdf = kwargs["layout_fun"](
                                                       ~~~~~~~~~~~~~~~~~~~~^
        imgwidthpx, imgheightpx, ndpi
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2868, in default_layout_fun
    imgwidthpdf = pagewidth = px_to_pt(imgwidthpx, ndpi[0])
                              ~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2616, in px_to_pt
    return 72.0 * length / dpi
           ~~~~~~~~~~~~~~^~~~~
ZeroDivisionError: division by zero

```

</details>

---

### 🟢 Crash #5: `SyntaxError`

- **Severity:** low
- **Input (hex):** `89504e470d0a1a0a0000000d49484452000000010000000108...`

<details>
<summary>Stack Trace</summary>

```
Traceback (most recent call last):
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\scripts\fuzzing_monitor.py", line 413, in _run_single_test
    self.fuzz_function(data)
    ~~~~~~~~~~~~~~~~~~^^^^^^
  File "C:\Users\kalin\OneDrive\Рабочий стол\Astra-3\fuzz\targets\img2pdf_convert.py", line 130, in fuzz_target
    pdf_bytes = img2pdf.convert([img_stream])
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3100, in convert
    pdf = convert_to_docobject(*images, **kwargs)
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 3022, in convert_to_docobject
    ) in read_images(
         ~~~~~~~~~~~^
        rawdata,
        ^^^^^^^^
    ...<3 lines>...
        kwargs["include_thumbnails"],
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ):
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 2300, in read_images
    color, ndpi, imgwidthpx, imgheightpx, rotation, iccp = get_imgmetadata(
                                                           ~~~~~~~~~~~~~~~^
        imgdata, imgformat, default_dpi, colorspace, rawdata, rot
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users\kalin\AppData\Local\Python\pythoncore-3.14-64\Lib\site-packages\img2pdf.py", line 1570, in get_imgmetadata
    if hasattr(imgdata, "getexif") and imgdata.getexif() is not None:
                                       ~
```

</details>

---

