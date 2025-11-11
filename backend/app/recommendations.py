"""
Recommendation generator for findings
Generates actionable recommendations based on finding type and severity
"""
from typing import Dict, Any, List
from app.models import Finding, Severity


def generate_recommendation(finding: Finding, scan_target: str) -> Dict[str, Any]:
    """Generate recommendation for a finding"""
    
    category = finding.category
    severity = finding.severity
    detail = finding.detail_json
    
    # Base recommendation structure
    recommendation = {
        "finding_id": finding.id,
        "scan_id": finding.scan_id,
        "priority": severity.value,
        "short_description": "",
        "technical_steps": "",
        "rollback_notes": "",
        "verification_steps": "",
        "effort_estimate": "",
        "confidence_score": 85,
        "compliance_mapping": "",
        "requires_privileged_action": "false",
    }
    
    # Generate recommendations based on category
    if category == "cert_expired":
        recommendation.update({
            "short_description": f"Перевыпустить сертификат для {scan_target}, т.к. он истёк.",
            "technical_steps": f"""1. Сгенерировать новый CSR:
   openssl req -new -newkey rsa:4096 -nodes -keyout {scan_target}.key -out {scan_target}.csr -subj "/CN={scan_target}"

2. Запросить выпуск сертификата у CA (Let's Encrypt, внутренний CA, или коммерческий)

3. Установить новый сертификат:
   - Для nginx: заменить файлы в /etc/nginx/ssl/ или /etc/nginx/certs/
   - Для Apache: обновить SSLCertificateFile и SSLCertificateKeyFile в конфигурации
   - Для HAProxy: обновить файл в bind строке (например, /etc/haproxy/certs/{scan_target}.pem)

4. Перезапустить сервис:
   systemctl reload nginx  # или apache2, haproxy
   # Или для Docker: docker restart <container_name>""",
            "rollback_notes": f"При проблемах вернуть старый сертификат из бэкапа /backup/certs/{scan_target}/ и выполнить reload сервиса.",
            "verification_steps": f"""1. Проверить expiry через openssl:
   echo | openssl s_client -servername {scan_target} -connect {scan_target}:443 2>/dev/null | openssl x509 -noout -dates

2. Выполнить re-scan через сканер

3. Проверить доступность сервиса:
   curl -v https://{scan_target}""",
            "effort_estimate": "Low (0.5-1 день)",
            "confidence_score": 95,
            "compliance_mapping": "Требования ЦБ РФ по управлению сертификатами; внутренний регламент PKI",
        })
    
    elif category == "cert_near_expiry":
        recommendation.update({
            "short_description": f"Обновить сертификат для {scan_target} до истечения срока действия.",
            "technical_steps": f"""1. Проверить дату истечения:
   echo | openssl s_client -servername {scan_target} -connect {scan_target}:443 2>/dev/null | openssl x509 -noout -enddate

2. Запланировать обновление за 30 дней до истечения

3. Сгенерировать CSR и запросить новый сертификат (см. инструкцию для cert_expired)

4. Настроить автоматическое обновление (например, certbot с cron или systemd timer)""",
            "verification_steps": f"Проверить дату истечения нового сертификата и убедиться, что автоматическое обновление настроено.",
            "effort_estimate": "Low (0.5 дня)",
            "confidence_score": 90,
        })
    
    elif category in ["small_rsa", "weak_key"]:
        key_size = detail.get("key_size", 1024)
        recommendation.update({
            "short_description": f"Увеличить размер RSA ключа до минимум 3072 бит (текущий: {key_size} бит).",
            "technical_steps": f"""1. Сгенерировать новый ключ с размером >= 3072 бит:
   openssl genrsa -out {scan_target}_new.key 4096

2. Создать CSR с новым ключом:
   openssl req -new -key {scan_target}_new.key -out {scan_target}_new.csr -subj "/CN={scan_target}"

3. Запросить новый сертификат у CA

4. Установить новый ключ и сертификат:
   - Обновить конфигурацию веб-сервера
   - Убедиться, что старый ключ удалён или архивирован

5. Перезапустить сервис""",
            "rollback_notes": "Вернуть старый ключ и сертификат из бэкапа при необходимости.",
            "verification_steps": f"""1. Проверить размер ключа:
   openssl rsa -in {scan_target}_new.key -text -noout | grep 'Private-Key'

2. Выполнить re-scan для подтверждения исправления""",
            "effort_estimate": "Medium (1-2 дня)",
            "confidence_score": 92,
            "compliance_mapping": "NIST SP 800-57 Part 1; требования к минимальному размеру ключа",
        })
    
    elif category == "deprecated_alg":
        protocol_or_cipher = detail.get("protocol") or detail.get("cipher", "unknown")
        recommendation.update({
            "short_description": f"Отключить устаревший протокол/шифр: {protocol_or_cipher}.",
            "technical_steps": f"""1. Для nginx - обновить ssl_protocols в конфигурации:
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers 'ECDHE-ECDHE-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
   ssl_prefer_server_ciphers on;

2. Для Apache - обновить SSLProtocol и SSLCipherSuite:
   SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
   SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384

3. Для HAProxy:
   ssl-default-bind-options ssl-min-ver TLSv1.2
   ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384

4. Перезагрузить конфигурацию:
   nginx -t && systemctl reload nginx
   # или для Apache: apache2ctl configtest && systemctl reload apache2""",
            "rollback_notes": "Вернуть предыдущую конфигурацию из git/бэкапа и перезагрузить сервис.",
            "verification_steps": f"""1. Проверить поддерживаемые протоколы:
   nmap --script ssl-enum-ciphers -p 443 {scan_target}

2. Выполнить testssl.sh для проверки:
   /opt/testssl.sh/testssl.sh {scan_target}

3. Выполнить re-scan""",
            "effort_estimate": "Low (0.5-1 день)",
            "confidence_score": 88,
            "compliance_mapping": "PCI-DSS 4.1; требования к TLS конфигурации",
        })
    
    elif category == "public_exposure":
        recommendation.update({
            "short_description": f"Провести аудит безопасности для публично доступного сервиса {scan_target}.",
            "technical_steps": f"""1. Проверить, что сервис должен быть публично доступен (бизнес-требование)

2. Если нет - переместить за firewall/VPN:
   - Настроить firewall правила
   - Настроить VPN доступ
   - Использовать reverse proxy с аутентификацией

3. Если да - усилить защиту:
   - Настроить WAF (Web Application Firewall)
   - Включить rate limiting
   - Настроить мониторинг и алерты
   - Регулярные security scans""",
            "verification_steps": "Проверить доступность через внешние сети и убедиться, что защита настроена.",
            "effort_estimate": "Medium (2-3 дня)",
            "confidence_score": 75,
        })
    
    elif category == "no_pqc_support":
        recommendation.update({
            "short_description": f"Внедрить поддержку Post-Quantum Cryptography для {scan_target}.",
            "technical_steps": f"""1. Оценить текущую инфраструктуру:
   - Определить используемые TLS библиотеки (OpenSSL, BoringSSL, NSS)
   - Проверить версии библиотек (требуется OpenSSL 3.0+ или BoringSSL с PQC поддержкой)
   - Определить используемые веб-серверы/прокси (nginx, Apache, HAProxy)

2. Выбрать стратегию миграции:
   
   Вариант A: Hybrid PQC (рекомендуется для начала)
   - Использовать hybrid алгоритмы (классический + PQC)
   - Примеры: X25519MLKEM768, SECP256R1MLKEM768
   - Обеспечивает обратную совместимость
   
   Вариант B: Pure PQC (для новых развертываний)
   - Использовать standalone PQC алгоритмы
   - Примеры: ML-KEM-768, ML-KEM-1024
   - Требует поддержки на всех клиентах

3. Обновить TLS библиотеки:
   
   Для OpenSSL:
   - Обновить до OpenSSL 3.0+ с поддержкой PQC
   - Или использовать OQS-OpenSSL (https://github.com/open-quantum-safe/openssl)
   
   Для nginx:
   - Пересобрать nginx с поддержкой PQC
   - Или использовать nginx-quic с PQC поддержкой
   
   Для Apache:
   - Обновить mod_ssl с поддержкой PQC
   - Пересобрать Apache с OQS-OpenSSL

4. Настроить TLS конфигурацию:

   Для nginx (пример hybrid):
   ssl_protocols TLSv1.3;
   ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
   # Добавить PQC группы в supported_groups
   # Требуется кастомная сборка nginx с PQC поддержкой

   Для Apache (пример):
   SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
   # Настроить PQC группы через mod_ssl

5. Тестирование:
   - Развернуть на тестовом окружении
   - Проверить совместимость с клиентами
   - Выполнить нагрузочное тестирование
   - Проверить производительность (PQC может быть медленнее)

6. Постепенное развертывание:
   - Включить hybrid режим сначала
   - Мониторить метрики производительности
   - Постепенно переходить на pure PQC

7. Документация и обучение:
   - Задокументировать изменения
   - Обучить команду поддержки
   - Обновить runbooks""",
            "rollback_notes": f"""При проблемах:
1. Вернуть предыдущую конфигурацию TLS
2. Откатить обновления библиотек
3. Проверить логи на наличие ошибок handshake
4. Убедиться, что старые клиенты могут подключиться""",
            "verification_steps": f"""1. Проверить поддержку PQC через сканер:
   python -m app.pqc_scanner {scan_target}

2. Проверить TLS handshake с PQC группами:
   openssl s_client -connect {scan_target}:443 -groups X25519MLKEM768

3. Выполнить re-scan через сканер для подтверждения

4. Проверить метрики производительности:
   - Время handshake
   - CPU использование
   - Пропускная способность

5. Проверить совместимость с клиентами:
   - Различные браузеры
   - Мобильные приложения
   - API клиенты""",
            "effort_estimate": "High (1-3 недели)",
            "confidence_score": 90,
            "compliance_mapping": "NIST PQC Migration Guidelines; EU PQC Roadmap 2030-2035; ЦБ РФ требования по криптографии",
        })
    
    elif category == "pqc_hybrid_only":
        recommendation.update({
            "short_description": f"Добавить поддержку standalone PQC алгоритмов для {scan_target} (сейчас только hybrid).",
            "technical_steps": f"""1. Текущее состояние:
   - Сервер поддерживает hybrid PQC алгоритмы: {', '.join(detail.get('hybrid_algos', []))}
   - Это хороший первый шаг, но рекомендуется добавить pure PQC

2. Добавить standalone PQC алгоритмы:
   - ML-KEM-768 (рекомендуется для большинства случаев)
   - ML-KEM-1024 (для высокого уровня безопасности)
   - ML-KEM-512 (для ограниченных ресурсов)

3. Обновить TLS конфигурацию:
   - Добавить pure PQC группы в supported_groups
   - Настроить приоритет: сначала hybrid, затем pure PQC
   - Обеспечить fallback на классические алгоритмы

4. Тестирование:
   - Проверить работу pure PQC алгоритмов
   - Убедиться в обратной совместимости
   - Проверить производительность""",
            "verification_steps": f"Выполнить re-scan и убедиться, что pure PQC алгоритмы поддерживаются.",
            "effort_estimate": "Medium (3-5 дней)",
            "confidence_score": 85,
            "compliance_mapping": "NIST PQC Migration Guidelines - переход от hybrid к pure PQC",
        })
    
    else:
        # Generic recommendation
        recommendation.update({
            "short_description": f"Исправить проблему безопасности: {category} для {scan_target}.",
            "technical_steps": f"1. Проанализировать finding: {finding.evidence}\n2. Применить соответствующие исправления\n3. Выполнить re-scan для проверки",
            "verification_steps": "Выполнить re-scan для подтверждения исправления.",
            "effort_estimate": "Medium (1-3 дня)",
            "confidence_score": 70,
        })
    
    return recommendation


def generate_recommendations_for_findings(findings: List[Finding], scan_target: str) -> List[Dict[str, Any]]:
    """Generate recommendations for all findings"""
    recommendations = []
    for finding in findings:
        rec = generate_recommendation(finding, scan_target)
        recommendations.append(rec)
    return recommendations

