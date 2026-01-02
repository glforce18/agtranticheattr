# AGTR Client (dinput.dll)

## Derleme

### GitHub Actions (Önerilen)
1. Bu klasördeki dosyaları GitHub'a yükle
2. Actions sekmesinden workflow oluştur (BUILD_YML_ICERIGI.txt'e bak)
3. Artifacts'ten `dinput.dll` indir

### Manuel
```bash
cmake -B build -G "Visual Studio 16 2019" -A Win32
cmake --build build --config Release
```

## Kurulum
1. Derlenen `dinput.dll` → Half-Life klasörüne koy
2. Oyunu başlat
3. Konsola yaz: `exec agtr_send.cfg`
