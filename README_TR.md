# Auditd PROCTITLE Decoder for rsyslog

> **Türkçe dokümantasyon**  
> English documentation: [`README.md`](README.md)

Linux `auditd` eventleri için geliştirilmiş küçük bir rsyslog enrichment aracıdır.

Linux Audit Framework tarafından üretilen `type=PROCTITLE` eventlerinde prosesin komut satırı çoğu zaman `proctitle=` alanında hexadecimal formatta tutulur. Bu proje ilgili hexadecimal değeri decode eder, evente okunabilir bir `decoded_proctitle="..."` alanı ekler ve enrich edilmiş eventi SIEM veya başka bir uzak syslog alıcısına iletir.

Orijinal `proctitle=` değeri korunur.

## Neden?

Ham bir audit eventi aşağıdakine benzer şekilde gelebilir:

```text
type=PROCTITLE msg=audit(...) proctitle=2F7573722F62696E2F6375726C002D6B
```

Decode işleminden sonra event:

```text
type=PROCTITLE msg=audit(...) proctitle=2F7573722F62696E2F6375726C002D6B decoded_proctitle="/usr/bin/curl -k"
```

haline gelir.

Böylece command-line telemetry:

- SIEM üzerinde daha kolay aranabilir,
- parser/custom property ile daha kolay ayrıştırılabilir,
- detection rule'larda doğrudan kullanılabilir,
- SOC analistleri tarafından investigation sırasında daha hızlı okunabilir

hale gelir.

## Mimari

```text
auditd
  |
  v
rsyslog
  |
  +---- normal eventler ---------------------> mevcut log akışı
  |
  +---- type=PROCTITLE
          |
          v
        omprog
          |
          v
      decode.sh
          |
          +---- HEX -> ASCII
          +---- NULL byte -> argv boşluğu
          +---- whitespace normalizasyonu
          +---- decoded_proctitle enrichment
          |
          v
       SIEM / syslog alıcısı
```

## Özellikler

- `type=PROCTITLE` eventlerini tespit eder.
- Hexadecimal `proctitle=` değerini çıkarır.
- Auditd tarafından argüman ayırıcı olarak kullanılan NULL byte'ları boşluğa dönüştürür.
- Yazdırılamayan karakterleri temizler.
- Tekrarlanan boşlukları normalize eder.
- Orijinal `proctitle=` alanını korur.
- Evente `decoded_proctitle="..."` alanı ekler.
- Decode edilen değer içindeki çift tırnak ve backslash karakterlerini escape eder.
- Mevcut syslog PRI değerini mümkün olduğunda korur.
- RFC3339/ISO timestamp formatını geleneksel syslog timestamp formatına dönüştürebilir.
- Daha önce `decoded_proctitle=` eklenmiş eventlerin yeniden işlenmesini engeller.
- Opsiyonel debug log desteği sunar.
- Decode ve UDP forwarding işlemlerinde Bash built-in özelliklerini kullanır.

## Gereksinimler

- Linux
- Bash
- rsyslog
- rsyslog `omprog` modülü
- AppArmor aktif kullanılıyorsa `apparmor-utils`

Aşağıdaki kurulum örnekleri Debian/Ubuntu tabanlı sistemler düşünülerek hazırlanmıştır. Diğer dağıtımlarda paket ve dosya yolları farklı olabilir.

## Kurulum

### 1. Gerekli paketleri yükleyin

```bash
sudo apt update
sudo apt install -y rsyslog apparmor-utils
```

Rsyslog servisinin çalıştığını kontrol edin:

```bash
systemctl status rsyslog
```

## 2. Decoder scriptini yükleyin

`decode.sh` dosyasını aşağıdaki konuma kopyalayın:

```text
/usr/local/bin/decode.sh
```

Çalıştırma iznini ve sahipliğini ayarlayın:

```bash
sudo chmod 750 /usr/local/bin/decode.sh
sudo chown root:root /usr/local/bin/decode.sh
```

## 3. SIEM/syslog hedefini yapılandırın

Script herhangi bir SIEM üreticisine özel değildir.

Aşağıdaki environment variable'lar kullanılabilir:

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SIEM_HOST` | `127.0.0.1` | Hedef SIEM/syslog hostname veya IP adresi |
| `SIEM_PORT` | `514` | Hedef UDP portu |
| `DEFAULT_PRI` | `<182>` | Gelen eventte PRI yoksa kullanılacak değer |
| `DEBUG` | `0` | Debug log için `1` yapılabilir |
| `DEBUG_FILE` | `/var/log/decode_proctitle.debug` | Tercih edilen debug log dosyası |

Rsyslog `omprog` kullanımında hedef bilgilerini decoder içine hard-code etmek yerine küçük bir wrapper script kullanılması önerilir.

Aşağıdaki dosyayı oluşturun:

```text
/usr/local/bin/decode-proctitle-wrapper.sh
```

İçeriği:

```bash
#!/usr/bin/env bash

export SIEM_HOST="192.0.2.10"
export SIEM_PORT="514"
export DEFAULT_PRI="<182>"
export DEBUG="0"

exec /usr/local/bin/decode.sh
```

`192.0.2.10` değerini kendi SIEM veya syslog alıcınızın adresiyle değiştirin.

Ardından:

```bash
sudo chmod 750 /usr/local/bin/decode-proctitle-wrapper.sh
sudo chown root:root /usr/local/bin/decode-proctitle-wrapper.sh
```

> `192.0.2.0/24` dokümantasyon amacıyla ayrılmış örnek bir IP bloğudur. Buradaki adres yalnızca örnek olarak kullanılmaktadır.

## 4. AppArmor yapılandırması

AppArmor rsyslog profili enforce durumundaysa rsyslog'un wrapper ve decoder scriptlerini çalıştırmasına izin verilmelidir.

Dosyayı açın:

```bash
sudo vi /etc/apparmor.d/usr.sbin.rsyslogd
```

Rsyslog profili içerisine gerekli execution izinlerini ekleyin:

```text
/usr/local/bin/decode-proctitle-wrapper.sh rix,
/usr/local/bin/decode.sh rix,
/usr/bin/bash ix,
/bin/bash ix,
```

Dağıtıma göre Bash yalnızca `/usr/bin/bash` veya `/bin/bash` altında bulunabilir.

Kontrol etmek için:

```bash
command -v bash
```

AppArmor profilini yeniden yükleyin:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd
```

Gerekirse AppArmor deny kayıtlarını kontrol edin:

```bash
sudo journalctl -k | grep -i apparmor
```

veya:

```bash
sudo dmesg | grep -i apparmor
```

## 5. rsyslog yapılandırması

Ana `/etc/rsyslog.conf` dosyasını doğrudan değiştirmek yerine ayrı bir config dosyası oluşturulması önerilir:

```text
/etc/rsyslog.d/40-auditd-proctitle-decoder.conf
```

İçerisine:

```text
module(load="omprog")

if (
    $rawmsg contains "type=PROCTITLE"
    and $rawmsg contains "proctitle="
    and not ($rawmsg contains "decoded_proctitle=")
) then {
    action(
        type="omprog"
        binary="/usr/local/bin/decode-proctitle-wrapper.sh"
    )

    stop
}
```

ekleyin.

### `stop` hakkında önemli not

`stop`, eşleşen eventin sonraki rsyslog kurallarında işlenmesini durdurur.

Bu projede enrich edilmiş eventin SIEM tarafında orijinal PROCTITLE eventinin yerine geçmesi isteniyorsa bu davranış uygundur.

Hem orijinal hem de enrich edilmiş PROCTITLE eventlerini farklı hedeflere göndermek istiyorsanız `stop` satırını kaldırmalı ve mevcut rsyslog routing yapınızı buna göre tasarlamalısınız.

## 6. rsyslog yapılandırmasını doğrulayın

Rsyslog'u restart etmeden önce config kontrolü yapın:

```bash
sudo rsyslogd -N1
```

Herhangi bir configuration error bulunmaması gerekir.

## 7. rsyslog servisini yeniden başlatın

```bash
sudo systemctl restart rsyslog
```

Durumu kontrol edin:

```bash
sudo systemctl status rsyslog
```

## Test

### Decoder'ı doğrudan test etme

Script rsyslog kullanılmadan da test edilebilir.

Test syslog alıcınızı hazırladıktan sonra:

```bash
printf '%s\n' \
'<182>2026-08-20T22:10:11.123456+03:00 linux01 auditd-info type=PROCTITLE msg=audit(1234567890.123:100): proctitle=2F7573722F62696E2F6375726C002D6B' \
| SIEM_HOST=192.0.2.10 SIEM_PORT=514 /usr/local/bin/decode.sh
```

Event içerisinde aşağıdaki enrich edilmiş alanın oluşması beklenir:

```text
decoded_proctitle="/usr/bin/curl -k"
```

### Gerçek audit eventi oluşturma

Auditd execution telemetry kaydı yapacak şekilde yapılandırılmışsa zararsız bir komut çalıştırabilirsiniz:

```bash
/usr/bin/printf 'proctitle-test\n'
```

Ardından audit loglarında veya SIEM üzerinde ilgili `type=PROCTITLE` eventini kontrol edin.

## Debug

Wrapper içerisindeki:

```bash
export DEBUG="0"
```

değerini:

```bash
export DEBUG="1"
```

olarak değiştirin.

Decoder öncelikle:

```text
/var/log/decode_proctitle.debug
```

dosyasına yazmayı dener.

Rsyslog/AppArmor context'i nedeniyle buraya yazamazsa:

```text
/tmp/decode_proctitle.debug
```

dosyasını kullanmayı dener.

Örneğin:

```bash
sudo tail -f /tmp/decode_proctitle.debug
```

Debug kayıtlarında aşağıdakine benzer satırlar görülebilir:

```text
IN:  <ham event>
OUT: <enrich edilmiş event>
```

## Sorun Giderme

### rsyslog restart olmuyor

Öncelikle config'i doğrulayın:

```bash
sudo rsyslogd -N1
```

Ardından servis loglarını kontrol edin:

```bash
sudo journalctl -u rsyslog -n 100 --no-pager
```

### Script manuel çalışıyor ancak rsyslog üzerinden çalışmıyor

İlk olarak AppArmor deny kayıtlarını kontrol edin:

```bash
sudo journalctl -k | grep -i apparmor
```

Dosya izinlerini de doğrulayın:

```bash
ls -l /usr/local/bin/decode.sh
ls -l /usr/local/bin/decode-proctitle-wrapper.sh
```

### Event decode ediliyor ancak SIEM'e ulaşmıyor

Linux sunucudan temel bağlantıyı kontrol edebilirsiniz:

```bash
nc -zvu 192.0.2.10 514
```

UDP bağlantı testinin gerçek event teslimatını garanti etmediğini unutmayın. SIEM/syslog receiver tarafında da eventin ulaşıp ulaşmadığını kontrol edin.

Güvenilir teslimat gereken ortamlarda `/dev/udp` yerine TCP veya TLS tabanlı forwarding tercih edilmesi değerlendirilmelidir.

### Duplicate event oluşuyor

Orijinal PROCTITLE eventinin başka bir rsyslog kuralı tarafından zaten SIEM'e gönderilip gönderilmediğini kontrol edin.

Örnek config:

```text
stop
```

kullanarak eşleşen orijinal eventin sonraki kurallara devam etmesini engeller.

### `decoded_proctitle` boş veya hatalı

Gelen eventin gerçekten hexadecimal bir değer içerdiğini kontrol edin:

```text
proctitle=<hex>
```

Decoder hexadecimal olmayan `proctitle` değerlerini bilinçli olarak işleme almaz.

## Güvenlik Notları

Bu proje rsyslog üzerinden `omprog` kullanarak harici bir program çalıştırır.

Öneriler:

- Decoder ve wrapper dosyalarının sahibi `root` olmalıdır.
- Rsyslog servis kullanıcısına script üzerinde write yetkisi verilmemelidir.
- Dosya izinları minimum gerekli seviyede tutulmalıdır.
- AppArmor izinları mümkün olduğunca dar tutulmalıdır.
- Production credential veya hassas bilgiler script içine hard-code edilmemelidir.
- Güvenilmeyen veya routed networklerde authenticated TLS syslog tercih edilmelidir.
- Değişiklikler önce test/non-production ortamında doğrulanmalıdır.
- `stop` kullanılmadan önce mevcut rsyslog routing yapısı incelenmelidir.

Bu utility yalnızca telemetry enrichment gerçekleştirir. Decode edilen komutun zararlı veya güvenli olduğuna ilişkin herhangi bir karar vermez.

## Repository Yapısı

```text
auditd-proctitle-decoder/
├── decode.sh
├── README.md
└── README_TR.md
```

## Detection Engineering Kullanımı

Enrich edilen alan detection rule ve threat hunting sorgularında kullanılabilir.

Örneğin:

```text
decoded_proctitle contains "curl"
decoded_proctitle contains "wget"
decoded_proctitle contains "chmod"
decoded_proctitle contains "base64"
```

Ancak bu ifadeler tek başına malicious kabul edilmemelidir.

Detection mantığında:

- kullanıcı,
- parent/child process ilişkileri,
- çalıştırma zamanı,
- hedef sistem,
- network bağlantıları,
- allow-list'ler,
- diğer audit telemetry

gibi ek context'lerin de değerlendirilmesi önerilir.

## Detection Engineering Açısından Yaklaşım

Bu projenin temel amacı yalnızca hexadecimal bir alanı decode etmek değildir.

Detection Engineering açısından telemetry'nin SIEM'e ulaşması kadar, **analiz edilebilir ve detection içerisinde kullanılabilir olması** da önemlidir.

Bu nedenle yaklaşım:

```text
Raw Telemetry
      |
      v
Normalization / Enrichment
      |
      v
Actionable Telemetry
      |
      +---- Detection
      +---- Threat Hunting
      +---- Investigation
      +---- Incident Response
```

şeklinde düşünülebilir.

Küçük bir log enrichment işlemi, aynı telemetry'yi kullanan birçok detection ve investigation sürecinin daha verimli hale gelmesini sağlayabilir.

## Lisans

Bu proje [MIT License](LICENSE) kapsamında yayınlanmaktadır.

Copyright (c) 2026 Sergen Yanmis.
