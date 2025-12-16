# Contributing to Firewall Report

**Repository:** [https://github.com/cumakurt/firewall_report](https://github.com/cumakurt/firewall_report)

Thank you for your interest in contributing to Firewall Report! This document provides guidelines and instructions for contributing.

> **Note:** This tool is specifically designed to analyze **Linux iptables firewall logs**. Contributions should maintain compatibility with iptables log format.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear title and description
- Steps to reproduce the bug
- Expected behavior
- Actual behavior
- Your environment (OS, Python version, etc.)
- Relevant log output or error messages

### Suggesting Features

Feature suggestions are welcome! Please open an issue with:
- A clear description of the feature
- Use cases and examples
- Potential implementation approach (if you have ideas)

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow PEP 8 style guidelines
   - Add comments for complex logic
   - Keep functions focused and modular
4. **Test your changes**
   - Test with different log formats
   - Test edge cases
5. **Commit your changes**
   ```bash
   git commit -m "Add: Description of your changes"
   ```
   Use clear commit messages:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Update:` for updates to existing features
   - `Refactor:` for code refactoring
   - `Docs:` for documentation changes
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**
   - Provide a clear description of your changes
   - Reference any related issues
   - Include examples if applicable

## Code Style

- Follow PEP 8 Python style guide
- Use meaningful variable and function names
- Keep functions small and focused
- Add docstrings for functions and classes
- Use type hints where appropriate

## Testing

While we don't have formal unit tests yet, please:
- Test your changes with real firewall logs
- Test edge cases (empty files, malformed logs, etc.)
- Verify HTML and JSON output formats
- Test with different date ranges and filters

## Questions?

If you have questions, feel free to open an issue with the `question` label.

---

# Firewall Report'a Katkıda Bulunma

**Repository:** [https://github.com/cumakurt/firewall_report](https://github.com/cumakurt/firewall_report)

Firewall Report'a katkıda bulunmakla ilgilendiğiniz için teşekkürler! Bu belge katkıda bulunma için yönergeler ve talimatlar sağlar.

> **Not:** Bu araç özellikle **Linux iptables firewall loglarını** analiz etmek için tasarlanmıştır. Katkılar iptables log formatı ile uyumluluğu korumalıdır.

## Nasıl Katkıda Bulunulur

### Hata Bildirme

Bir hata bulursanız, lütfen şunlarla bir issue açın:
- Açık bir başlık ve açıklama
- Hatayı yeniden üretme adımları
- Beklenen davranış
- Gerçek davranış
- Ortamınız (OS, Python sürümü, vb.)
- İlgili log çıktısı veya hata mesajları

### Özellik Önerileri

Özellik önerileri memnuniyetle karşılanır! Lütfen şunlarla bir issue açın:
- Özelliğin açık bir açıklaması
- Kullanım durumları ve örnekler
- Potansiyel uygulama yaklaşımı (fikirleriniz varsa)

### Kod Katkıları

1. **Repository'yi fork edin**
2. **Bir özellik dalı oluşturun**
   ```bash
   git checkout -b feature/ozellik-adi
   ```
3. **Değişikliklerinizi yapın**
   - PEP 8 stil yönergelerini takip edin
   - Karmaşık mantık için yorumlar ekleyin
   - Fonksiyonları odaklı ve modüler tutun
4. **Değişikliklerinizi test edin**
   - Farklı log formatlarıyla test edin
   - Edge case'leri test edin
5. **Değişikliklerinizi commit edin**
   ```bash
   git commit -m "Add: Değişikliklerinizin açıklaması"
   ```
   Açık commit mesajları kullanın:
   - `Add:` yeni özellikler için
   - `Fix:` hata düzeltmeleri için
   - `Update:` mevcut özelliklerde güncellemeler için
   - `Refactor:` kod refaktoring için
   - `Docs:` dokümantasyon değişiklikleri için
6. **Fork'unuza push edin**
   ```bash
   git push origin feature/ozellik-adi
   ```
7. **Bir Pull Request açın**
   - Değişikliklerinizin açık bir açıklamasını sağlayın
   - İlgili issue'ları referans edin
   - Uygulanabilirse örnekler ekleyin

## Kod Stili

- PEP 8 Python stil kılavuzunu takip edin
- Anlamlı değişken ve fonksiyon adları kullanın
- Fonksiyonları küçük ve odaklı tutun
- Fonksiyonlar ve sınıflar için docstring'ler ekleyin
- Uygun yerlerde type hint'ler kullanın

## Test Etme

Henüz resmi unit testlerimiz olmasa da, lütfen:
- Değişikliklerinizi gerçek firewall loglarıyla test edin
- Edge case'leri test edin (boş dosyalar, hatalı loglar, vb.)
- HTML ve JSON çıktı formatlarını doğrulayın
- Farklı tarih aralıkları ve filtrelerle test edin

## Sorularınız mı var?

Sorularınız varsa, lütfen `question` etiketiyle bir issue açmaktan çekinmeyin.

