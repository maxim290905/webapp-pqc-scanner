# Roadmap развития продукта Cryptography Vulnerability Scanner

## 🎯 Три ключевых направления развития

Этот документ описывает стратегию улучшения проекта по трем направлениям:
1. **Соответствие регуляторам РФ** (ФСТЭК, ФСБ, ГОСТ)
2. **Расширение на криптоактивы** (репозитории, контейнеры, SBOM)
3. **Развитие бизнес-логики** (автоматизация, аналитика, интеграции)

---

## 📜 Часть 1: Соответствие регуляторам РФ

### Текущая ситуация
Сканер проверяет общие стандарты (PCI-DSS, TLS best practices), но не адаптирован под российские требования.

### Целевые регуляторы и стандарты

#### 1.1. **ФСТЭК России (Федеральная служба по техническому и экспортному контролю)**

##### Требования ФСТЭК к криптографии:
- **Приказ ФСТЭК №17** (2014): Требования по защите персональных данных
- **Приказ ФСТЭК №21** (2013): Требования к ИСПДн
- **Приказ ФСТЭК №239** (2023): Требования к квантово-устойчивой криптографии

##### Что нужно проверять:
✅ **Сертифицированные средства криптозащиты**
- Только алгоритмы из ГОСТ Р 34.10-2012 (ЭЦП)
- Только алгоритмы из ГОСТ Р 34.11-2012 (хэширование Стрибог)
- ГОСТ Р 34.12-2015 (шифрование Кузнечик, Магма)
- Запрет на использование несертифицированных алгоритмов (RSA, ECDSA) для государственных систем

✅ **Уровни защищенности ИСПДн**
- **УЗ-1** (высокий): обязательное использование СКЗИ, сертифицированных ФСБ
- **УЗ-2** (средний): СКЗИ + дополнительные меры
- **УЗ-3** (базовый): минимальные требования
- **УЗ-4** (минимальный): упрощенные требования

✅ **Квантово-устойчивая криптография (с 2025)**
- ГОСТ Р 34.10-2023 (квантово-устойчивая ЭЦП)
- Гибридные схемы (классика + PQC)
- Обязательно для КИИ (критическая информационная инфраструктура)

##### Реализация в проекте:

```python
# backend/app/compliance/fstec.py
class FSTECComplianceChecker:
    """
    Проверка соответствия требованиям ФСТЭК
    """
    
    GOST_ALGORITHMS = {
        'signature': ['GOST R 34.10-2012', 'GOST R 34.10-2023'],
        'hash': ['GOST R 34.11-2012', 'Streebog-256', 'Streebog-512'],
        'cipher': ['GOST R 34.12-2015', 'Kuznyechik', 'Magma']
    }
    
    PROHIBITED_FOR_GOV = [
        'RSA', 'ECDSA', 'SHA-1', 'MD5', 'DES', '3DES', 'RC4'
    ]
    
    def check_uz_level(self, scan_results: dict, target_uz: int) -> dict:
        """
        Проверка соответствия уровню защищенности УЗ-1 до УЗ-4
        """
        findings = []
        
        # УЗ-1: Только ГОСТ алгоритмы
        if target_uz == 1:
            if not self._uses_only_gost(scan_results):
                findings.append({
                    'severity': 'P0',
                    'category': 'fstec_uz1_violation',
                    'description': 'Для УЗ-1 разрешены только сертифицированные ГОСТ алгоритмы',
                    'remediation': 'Заменить RSA/ECDSA на ГОСТ Р 34.10-2012'
                })
        
        # Проверка на использование запрещенных алгоритмов
        for prohibited in self.PROHIBITED_FOR_GOV:
            if prohibited in scan_results.get('algorithms', []):
                findings.append({
                    'severity': 'P0',
                    'category': 'fstec_prohibited_algo',
                    'description': f'Использование {prohibited} запрещено для госсистем',
                    'regulation': 'ФСТЭК Приказ №17'
                })
        
        return {
            'compliant': len(findings) == 0,
            'uz_level': target_uz,
            'findings': findings
        }
```

##### Новые проверки (добавить в scanner.py):

```python
# Проверка 1: Детектирование ГОСТ алгоритмов
def detect_gost_support(target: str, port: int = 443) -> dict:
    """
    Проверка поддержки ГОСТ TLS cipher suites
    
    ГОСТ cipher suites:
    - TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
    - TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
    - TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
    """
    gost_ciphers = [
        0xC100,  # GOST 2012-256
        0xC101,  # GOST 2012-512
        0xFF85,  # GOST 28147-89
    ]
    
    # Отправить ClientHello с ГОСТ cipher suites
    # Аналогично PQC сканеру, но для ГОСТ
    pass

# Проверка 2: Валидация сертификатов ФСБ
def verify_fsb_certificate(cert_data: dict) -> dict:
    """
    Проверка, что сертификат выдан аккредитованным УЦ ФСБ
    """
    accredited_cas = [
        'CN=Russian Trusted Root CA',
        'CN=CryptoPro',
        # Полный список из реестра Минцифры
    ]
    
    issuer = cert_data.get('issuer')
    is_accredited = any(ca in issuer for ca in accredited_cas)
    
    return {
        'is_accredited': is_accredited,
        'issuer': issuer,
        'warning': None if is_accredited else 'Сертификат не от аккредитованного УЦ'
    }
```

#### 1.2. **ФСБ России (Служба безопасности)**

##### Требования ФСБ:
- **Приказ ФСБ №378** (2015): Требования к СКЗИ
- **Лицензирование**: Обязательно для СКЗИ класса КС1, КС2, КС3
- **Сертификация**: Обязательна для КИИ и госсистем

##### Что проверять:
✅ Использование только лицензированных СКЗИ  
✅ Соответствие классу защиты (КС1-КС3)  
✅ Актуальность лицензий и сертификатов

##### Реализация:

```python
# backend/app/compliance/fsb.py
class FSBComplianceChecker:
    """
    Проверка соответствия требованиям ФСБ
    """
    
    LICENSED_SKZI = {
        'CryptoPro CSP': {'classes': ['KC1', 'KC2'], 'valid_until': '2026-12-31'},
        'ViPNet': {'classes': ['KC1'], 'valid_until': '2027-06-30'},
        'Signal-COM': {'classes': ['KC2'], 'valid_until': '2025-12-31'},
    }
    
    def check_skzi_license(self, detected_skzi: str) -> dict:
        """
        Проверка лицензии СКЗИ
        """
        if detected_skzi not in self.LICENSED_SKZI:
            return {
                'compliant': False,
                'error': f'СКЗИ {detected_skzi} не найдено в реестре ФСБ'
            }
        
        skzi_info = self.LICENSED_SKZI[detected_skzi]
        # Проверка срока действия лицензии
        # ...
        
        return {
            'compliant': True,
            'skzi': detected_skzi,
            'classes': skzi_info['classes']
        }
```

#### 1.3. **ГОСТ стандарты**

##### Ключевые ГОСТы для проверки:
- **ГОСТ Р 34.10-2012**: Электронная цифровая подпись
- **ГОСТ Р 34.11-2012**: Хэш-функция Стрибог
- **ГОСТ Р 34.12-2015**: Шифрование (Кузнечик, Магма)
- **ГОСТ Р 34.13-2015**: Режимы работы блочных шифров
- **ГОСТ 28147-89**: Устаревший, но еще используется

##### Детектирование ГОСТ:

```python
def detect_gost_in_certificate(cert: dict) -> dict:
    """
    Определение использования ГОСТ в сертификате
    """
    gost_oids = {
        '1.2.643.7.1.1.1.1': 'GOST R 34.10-2012 (256 bit)',
        '1.2.643.7.1.1.1.2': 'GOST R 34.10-2012 (512 bit)',
        '1.2.643.7.1.1.2.2': 'GOST R 34.11-2012 (Streebog 256)',
        '1.2.643.7.1.1.2.3': 'GOST R 34.11-2012 (Streebog 512)',
    }
    
    signature_algorithm = cert.get('signature_algorithm')
    
    for oid, name in gost_oids.items():
        if oid in signature_algorithm:
            return {
                'uses_gost': True,
                'algorithm': name,
                'oid': oid
            }
    
    return {
        'uses_gost': False,
        'warning': 'Сертификат не использует ГОСТ алгоритмы'
    }
```

### Новый модуль: Compliance Score для РФ

```python
# backend/app/compliance/rf_score.py
class RFComplianceScore:
    """
    Оценка соответствия российским требованиям (аналог PQ-Score)
    
    RF-Score (0-100):
    - 100: Полное соответствие ГОСТ/ФСТЭК/ФСБ
    - 0: Критические нарушения
    """
    
    WEIGHTS = {
        'gost_usage': 0.40,        # 40% - использование ГОСТ
        'fstec_compliance': 0.30,  # 30% - соответствие ФСТЭК
        'fsb_skzi': 0.20,          # 20% - лицензированные СКЗИ
        'cert_validity': 0.10,     # 10% - валидность сертификатов
    }
    
    def calculate(self, scan_results: dict, target_sector: str) -> dict:
        """
        Расчет RF-Score
        
        target_sector: 'government', 'finance', 'healthcare', 'commercial'
        """
        scores = {}
        
        # 1. Оценка использования ГОСТ
        gost_score = self._evaluate_gost_usage(scan_results)
        scores['gost_usage'] = gost_score
        
        # 2. Оценка ФСТЭК (только для госсектора и КИИ)
        if target_sector in ['government', 'critical_infrastructure']:
            fstec_score = self._evaluate_fstec(scan_results)
        else:
            fstec_score = 1.0  # Не обязательно для коммерции
        scores['fstec_compliance'] = fstec_score
        
        # 3. Оценка СКЗИ
        skzi_score = self._evaluate_skzi(scan_results)
        scores['fsb_skzi'] = skzi_score
        
        # 4. Валидность сертификатов
        cert_score = self._evaluate_certificates(scan_results)
        scores['cert_validity'] = cert_score
        
        # Финальный расчет
        rf_score = sum(
            scores[key] * self.WEIGHTS[key]
            for key in self.WEIGHTS
        )
        
        return {
            'rf_score': round(rf_score * 100),
            'components': scores,
            'risk_level': self._get_risk_level(rf_score * 100),
            'sector': target_sector
        }
```

### API изменения

```python
# backend/app/schemas.py
class ScanCreate(BaseModel):
    target: str
    scan_type: str = "tls_network"
    project_id: Optional[int] = None
    
    # Новые поля для РФ compliance
    check_rf_compliance: bool = False
    target_sector: str = "commercial"  # government, finance, healthcare, critical_infrastructure
    target_uz_level: Optional[int] = None  # 1-4 для ФСТЭК

# backend/app/main.py
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # ... существующий код ...
    
    # Добавить RF compliance в метаданные скана
    if scan.check_rf_compliance:
        scan_record.metadata = {
            'rf_compliance': True,
            'target_sector': scan.target_sector,
            'uz_level': scan.target_uz_level
        }
```

### PDF отчет с RF compliance

```python
# backend/app/report_generator.py
def generate_rf_compliance_section(rf_score_data: dict) -> str:
    """
    Генерация секции с RF compliance для PDF
    """
    template = """
    <div class="rf-compliance">
        <h2>🇷🇺 Соответствие требованиям РФ</h2>
        
        <div class="rf-score">
            <h3>RF-Score: {{ rf_score }}/100</h3>
            <div class="risk-level {{ risk_level }}">
                Уровень риска: {{ risk_level }}
            </div>
        </div>
        
        <div class="compliance-details">
            <h4>ГОСТ алгоритмы</h4>
            {% if gost_detected %}
                <p class="success">✅ Обнаружено использование ГОСТ</p>
                <ul>
                {% for algo in gost_algorithms %}
                    <li>{{ algo }}</li>
                {% endfor %}
                </ul>
            {% else %}
                <p class="warning">⚠️ ГОСТ алгоритмы не обнаружены</p>
            {% endif %}
            
            <h4>ФСТЭК соответствие</h4>
            {% if fstec_compliant %}
                <p class="success">✅ Соответствует требованиям ФСТЭК</p>
            {% else %}
                <p class="error">❌ Не соответствует требованиям ФСТЭК</p>
                <ul>
                {% for violation in fstec_violations %}
                    <li>{{ violation }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        </div>
        
        <div class="recommendations">
            <h4>Рекомендации по соответствию</h4>
            <ol>
                <li>Внедрить сертифицированное СКЗИ (CryptoPro CSP, ViPNet)</li>
                <li>Перейти на ГОСТ Р 34.10-2012 для ЭЦП</li>
                <li>Использовать Стрибог (ГОСТ Р 34.11-2012) вместо SHA-256</li>
                <li>Получить сертификацию ФСБ для СКЗИ</li>
            </ol>
        </div>
    </div>
    """
    # Рендеринг с Jinja2
```

---

## 🔐 Часть 2: Расширение на криптоактивы (репозитории, SBOM, контейнеры)

### Текущая ситуация
Сканер работает только с доменами/IP и проверяет TLS. Нужно расширить на:
- Git репозитории
- Docker контейнеры
- Бинарные файлы
- SBOM (Software Bill of Materials)

### 2.1. **Сканирование Git репозиториев**

#### Что проверять в репозиториях:
✅ Хардкоженные ключи и секреты  
✅ Устаревшие криптобиблиотеки  
✅ Небезопасное использование крипто-API  
✅ Слабые алгоритмы в коде  

#### Реализация:

```python
# backend/app/scanners/repository_scanner.py
class RepositoryScanner:
    """
    Сканирование Git репозиториев на криптоуязвимости
    """
    
    def __init__(self):
        self.secret_patterns = [
            r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            r'sk-[a-zA-Z0-9]{32,}',  # Stripe secret keys
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub tokens
            r'AKIA[0-9A-Z]{16}',     # AWS access keys
        ]
        
        self.crypto_patterns = {
            'weak_hash': [
                r'hashlib\.md5\(',
                r'hashlib\.sha1\(',
                r'MD5\.',
                r'SHA1\.',
            ],
            'weak_cipher': [
                r'DES\.',
                r'RC4\.',
                r'Blowfish\.',
            ],
            'hardcoded_keys': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
            ]
        }
    
    async def scan_repository(self, repo_url: str, branch: str = 'main') -> dict:
        """
        Основной метод сканирования репозитория
        """
        findings = []
        
        # 1. Клонировать репозиторий (shallow clone)
        repo_path = await self._clone_repo(repo_url, branch)
        
        # 2. Сканировать файлы
        for file_path in self._get_code_files(repo_path):
            file_findings = await self._scan_file(file_path)
            findings.extend(file_findings)
        
        # 3. Сканировать зависимости
        dependency_findings = await self._scan_dependencies(repo_path)
        findings.extend(dependency_findings)
        
        # 4. Проверить историю коммитов (секреты в старых коммитах)
        history_findings = await self._scan_git_history(repo_path)
        findings.extend(history_findings)
        
        # 5. Очистка
        await self._cleanup(repo_path)
        
        return {
            'repository': repo_url,
            'branch': branch,
            'total_findings': len(findings),
            'findings': findings,
            'crypto_score': self._calculate_crypto_score(findings)
        }
    
    async def _scan_file(self, file_path: str) -> List[dict]:
        """
        Сканирование отдельного файла
        """
        findings = []
        
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            line_number = 0
            
            for line in content.split('\n'):
                line_number += 1
                
                # Проверка на секреты
                for pattern in self.secret_patterns:
                    if re.search(pattern, line):
                        findings.append({
                            'type': 'hardcoded_secret',
                            'severity': 'P0',
                            'file': file_path,
                            'line': line_number,
                            'description': 'Обнаружен хардкоженный секрет/ключ'
                        })
                
                # Проверка на слабые хеш-функции
                for pattern in self.crypto_patterns['weak_hash']:
                    if re.search(pattern, line):
                        findings.append({
                            'type': 'weak_cryptography',
                            'severity': 'P1',
                            'file': file_path,
                            'line': line_number,
                            'description': 'Использование слабой хеш-функции (MD5/SHA1)'
                        })
        
        return findings
    
    async def _scan_dependencies(self, repo_path: str) -> List[dict]:
        """
        Сканирование зависимостей (requirements.txt, package.json, go.mod)
        """
        findings = []
        
        # Python dependencies
        req_file = os.path.join(repo_path, 'requirements.txt')
        if os.path.exists(req_file):
            findings.extend(await self._check_python_deps(req_file))
        
        # Node.js dependencies
        package_file = os.path.join(repo_path, 'package.json')
        if os.path.exists(package_file):
            findings.extend(await self._check_node_deps(package_file))
        
        # Go dependencies
        go_mod = os.path.join(repo_path, 'go.mod')
        if os.path.exists(go_mod):
            findings.extend(await self._check_go_deps(go_mod))
        
        return findings
    
    async def _check_python_deps(self, req_file: str) -> List[dict]:
        """
        Проверка Python зависимостей на уязвимости
        """
        findings = []
        
        # Устаревшие/уязвимые крипто-библиотеки
        vulnerable_packages = {
            'pycrypto': 'Deprecated, use pycryptodome instead',
            'pyDes': 'Weak encryption (DES)',
            'cryptography<3.0': 'Outdated cryptography version',
        }
        
        with open(req_file, 'r') as f:
            for line in f:
                package = line.strip().split('==')[0]
                
                if package in vulnerable_packages:
                    findings.append({
                        'type': 'vulnerable_dependency',
                        'severity': 'P1',
                        'package': package,
                        'description': vulnerable_packages[package]
                    })
        
        return findings
```

#### API для сканирования репозиториев:

```python
# backend/app/schemas.py
class RepositoryScanCreate(BaseModel):
    repository_url: str  # https://github.com/user/repo
    branch: str = "main"
    project_id: Optional[int] = None
    scan_credentials: Optional[dict] = None  # Для приватных репо

# backend/app/main.py
@app.post("/api/scans/repository", response_model=ScanResponse)
async def scan_repository(
    scan: RepositoryScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Сканирование Git репозитория
    """
    # Создать запись скана
    scan_record = Scan(
        target=scan.repository_url,
        scan_type="repository",
        status=ScanStatus.PENDING,
        user_id=current_user.id,
        project_id=scan.project_id
    )
    db.add(scan_record)
    db.commit()
    
    # Запустить Celery task
    task = repository_scan_task.delay(
        scan_id=scan_record.id,
        repo_url=scan.repository_url,
        branch=scan.branch
    )
    
    return scan_record
```

### 2.2. **SBOM (Software Bill of Materials) анализ**

#### Что такое SBOM:
- Список всех компонентов и зависимостей в ПО
- Форматы: CycloneDX, SPDX, SWID
- Обязателен для госзакупок в США (Executive Order 14028)

#### Реализация:

```python
# backend/app/scanners/sbom_scanner.py
class SBOMScanner:
    """
    Анализ SBOM на криптоуязвимости
    """
    
    def __init__(self):
        # База данных уязвимостей
        self.vuln_db = self._load_vulnerability_database()
    
    async def analyze_sbom(self, sbom_file: str, format: str = 'cyclonedx') -> dict:
        """
        Анализ SBOM файла
        
        format: 'cyclonedx', 'spdx', 'swid'
        """
        # 1. Парсинг SBOM
        components = self._parse_sbom(sbom_file, format)
        
        findings = []
        
        # 2. Для каждого компонента проверить уязвимости
        for component in components:
            vulns = await self._check_vulnerabilities(
                name=component['name'],
                version=component['version']
            )
            
            for vuln in vulns:
                findings.append({
                    'component': component['name'],
                    'version': component['version'],
                    'vulnerability': vuln['id'],  # CVE-2023-XXXX
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'remediation': vuln['fixed_in']
                })
        
        # 3. Специальная проверка криптобиблиотек
        crypto_findings = self._check_crypto_libraries(components)
        findings.extend(crypto_findings)
        
        return {
            'total_components': len(components),
            'vulnerable_components': len(set(f['component'] for f in findings)),
            'findings': findings,
            'crypto_score': self._calculate_crypto_score(findings)
        }
    
    def _check_crypto_libraries(self, components: List[dict]) -> List[dict]:
        """
        Специальная проверка криптографических библиотек
        """
        crypto_libraries = {
            'openssl': {
                'min_version': '1.1.1',
                'recommended': '3.0.0',
                'vulnerabilities': ['CVE-2022-0778', 'Heartbleed']
            },
            'cryptography': {
                'min_version': '3.0',
                'recommended': '41.0',
            },
            'pycrypto': {
                'status': 'deprecated',
                'replacement': 'pycryptodome'
            }
        }
        
        findings = []
        
        for component in components:
            name = component['name'].lower()
            version = component['version']
            
            if name in crypto_libraries:
                lib_info = crypto_libraries[name]
                
                if lib_info.get('status') == 'deprecated':
                    findings.append({
                        'type': 'deprecated_crypto_library',
                        'severity': 'P0',
                        'component': name,
                        'description': f'{name} устарела, используйте {lib_info["replacement"]}'
                    })
                
                elif version < lib_info['min_version']:
                    findings.append({
                        'type': 'outdated_crypto_library',
                        'severity': 'P1',
                        'component': name,
                        'version': version,
                        'description': f'Версия {version} устарела, обновите до {lib_info["recommended"]}'
                    })
        
        return findings
```

### 2.3. **Сканирование Docker контейнеров**

```python
# backend/app/scanners/container_scanner.py
class ContainerScanner:
    """
    Сканирование Docker образов на криптоуязвимости
    """
    
    async def scan_container(self, image: str) -> dict:
        """
        Сканирование Docker образа
        
        image: 'nginx:latest', 'myregistry.com/myapp:v1.0'
        """
        findings = []
        
        # 1. Извлечь SBOM из контейнера (если есть)
        sbom = await self._extract_sbom(image)
        if sbom:
            sbom_findings = await SBOMScanner().analyze_sbom(sbom)
            findings.extend(sbom_findings['findings'])
        
        # 2. Сканировать установленные пакеты
        packages = await self._get_installed_packages(image)
        for package in packages:
            vulns = await self._check_package_vulnerabilities(package)
            findings.extend(vulns)
        
        # 3. Проверить конфигурацию TLS/SSL в контейнере
        tls_config = await self._check_tls_config(image)
        if tls_config['issues']:
            findings.extend(tls_config['issues'])
        
        # 4. Проверить сертификаты в контейнере
        certs = await self._find_certificates(image)
        for cert in certs:
            cert_findings = await self._analyze_certificate(cert)
            findings.extend(cert_findings)
        
        return {
            'image': image,
            'total_findings': len(findings),
            'findings': findings,
            'container_score': self._calculate_container_score(findings)
        }
```

### 2.4. **Unified Scan API (все типы активов)**

```python
# backend/app/schemas.py
class UnifiedScanCreate(BaseModel):
    """
    Универсальное API для сканирования любых активов
    """
    target: str
    scan_type: str  # 'domain', 'repository', 'container', 'sbom', 'binary'
    project_id: Optional[int] = None
    
    # Дополнительные параметры в зависимости от типа
    options: Optional[dict] = None
    
    # Для репозиториев
    # options = {'branch': 'main', 'credentials': {...}}
    
    # Для контейнеров
    # options = {'registry_auth': {...}}
    
    # Для SBOM
    # options = {'format': 'cyclonedx'}

# backend/app/main.py
@app.post("/api/scans/unified", response_model=ScanResponse)
async def create_unified_scan(
    scan: UnifiedScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Универсальное API для любых типов сканов
    """
    # Роутинг на специализированные сканеры
    scanner_map = {
        'domain': domain_scan_task,
        'repository': repository_scan_task,
        'container': container_scan_task,
        'sbom': sbom_scan_task,
    }
    
    task_func = scanner_map.get(scan.scan_type)
    if not task_func:
        raise HTTPException(400, f"Unknown scan type: {scan.scan_type}")
    
    # Создать запись
    scan_record = Scan(
        target=scan.target,
        scan_type=scan.scan_type,
        status=ScanStatus.PENDING,
        user_id=current_user.id,
        project_id=scan.project_id
    )
    db.add(scan_record)
    db.commit()
    
    # Запустить task
    task = task_func.delay(
        scan_id=scan_record.id,
        target=scan.target,
        options=scan.options or {}
    )
    
    return scan_record
```

---

## 💼 Часть 3: Развитие бизнес-логики продукта

### 3.1. **Автоматизация и оркестрация**

#### Continuous Security Monitoring

```python
# backend/app/automation/scheduler.py
class ContinuousMonitoring:
    """
    Непрерывный мониторинг безопасности
    """
    
    async def setup_monitoring(
        self,
        project_id: int,
        targets: List[str],
        frequency: str = 'daily',  # hourly, daily, weekly, monthly
        alert_channels: List[str] = None
    ):
        """
        Настройка непрерывного мониторинга
        """
        # 1. Создать расписание в Celery Beat
        schedule = {
            'task': 'app.tasks.automated_scan',
            'schedule': self._get_schedule(frequency),
            'args': (project_id, targets),
        }
        
        # 2. Настроить алерты
        if alert_channels:
            self._setup_alerts(project_id, alert_channels)
        
        return schedule
    
    def _get_schedule(self, frequency: str):
        """
        Преобразование frequency в Celery schedule
        """
        schedules = {
            'hourly': crontab(minute=0),
            'daily': crontab(hour=2, minute=0),  # 2 AM
            'weekly': crontab(hour=2, minute=0, day_of_week=1),  # Monday
            'monthly': crontab(hour=2, minute=0, day_of_month=1),
        }
        return schedules.get(frequency, schedules['daily'])
```

#### Policy Engine (политики безопасности)

```python
# backend/app/automation/policy_engine.py
class PolicyEngine:
    """
    Движок политик безопасности
    """
    
    def __init__(self):
        self.policies = []
    
    def add_policy(self, policy: dict):
        """
        Добавить политику безопасности
        
        Пример политики:
        {
            'name': 'Block weak TLS',
            'condition': 'pq_score > 60',
            'action': 'block_deployment',
            'notify': ['security@company.com']
        }
        """
        self.policies.append(policy)
    
    async def evaluate(self, scan_results: dict) -> dict:
        """
        Оценить результаты скана по всем политикам
        """
        violations = []
        actions = []
        
        for policy in self.policies:
            if self._evaluate_condition(policy['condition'], scan_results):
                violations.append(policy['name'])
                actions.append(policy['action'])
                
                # Выполнить действие
                await self._execute_action(policy, scan_results)
        
        return {
            'violations': violations,
            'actions_taken': actions,
            'compliant': len(violations) == 0
        }
    
    def _evaluate_condition(self, condition: str, scan_results: dict) -> bool:
        """
        Оценить условие (простой DSL)
        """
        # Безопасная оценка условий
        allowed_vars = {
            'pq_score': scan_results.get('pq_score', 0),
            'rf_score': scan_results.get('rf_score', 0),
            'findings_count': len(scan_results.get('findings', [])),
        }
        
        try:
            return eval(condition, {"__builtins__": {}}, allowed_vars)
        except:
            return False
    
    async def _execute_action(self, policy: dict, scan_results: dict):
        """
        Выполнить действие по политике
        """
        action = policy['action']
        
        if action == 'block_deployment':
            # Интеграция с CI/CD для блокировки деплоя
            await self._block_ci_cd(scan_results)
        
        elif action == 'notify':
            # Отправить уведомления
            await self._send_notifications(
                recipients=policy['notify'],
                scan_results=scan_results
            )
        
        elif action == 'create_ticket':
            # Создать тикет в Jira/ServiceNow
            await self._create_ticket(scan_results)
```

### 3.2. **Аналитика и BI**

#### Trending и исторический анализ

```python
# backend/app/analytics/trends.py
class SecurityTrends:
    """
    Анализ трендов безопасности
    """
    
    async def get_trend_analysis(
        self,
        project_id: int,
        timeframe: str = '30d'  # 7d, 30d, 90d, 1y
    ) -> dict:
        """
        Анализ трендов за период
        """
        scans = await self._get_historical_scans(project_id, timeframe)
        
        return {
            'pq_score_trend': self._calculate_trend([s.pq_score for s in scans]),
            'findings_trend': self._calculate_trend([len(s.findings) for s in scans]),
            'risk_level_changes': self._analyze_risk_changes(scans),
            'top_vulnerabilities': self._get_top_vulnerabilities(scans),
            'remediation_velocity': self._calculate_remediation_velocity(scans),
        }
    
    def _calculate_trend(self, values: List[float]) -> dict:
        """
        Расчет тренда (растет/падает/стабильно)
        """
        if len(values) < 2:
            return {'trend': 'insufficient_data'}
        
        # Линейная регрессия
        slope = self._linear_regression(values)
        
        if slope > 0.1:
            direction = 'improving'
        elif slope < -0.1:
            direction = 'deteriorating'
        else:
            direction = 'stable'
        
        return {
            'trend': direction,
            'slope': slope,
            'values': values
        }
```

#### Dashboard API

```python
# backend/app/main.py
@app.get("/api/analytics/dashboard")
async def get_security_dashboard(
    project_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Unified security dashboard
    """
    # 1. Текущий статус
    current_status = await get_current_security_status(project_id, db)
    
    # 2. Тренды
    trends = await SecurityTrends().get_trend_analysis(project_id)
    
    # 3. Top проблемы
    top_issues = await get_top_security_issues(project_id, db)
    
    # 4. Compliance статус
    compliance = await get_compliance_status(project_id, db)
    
    return {
        'status': current_status,
        'trends': trends,
        'top_issues': top_issues,
        'compliance': compliance,
        'generated_at': datetime.now().isoformat()
    }
```

### 3.3. **Интеграции**

#### CI/CD интеграция

```python
# backend/app/integrations/cicd.py
class CICDIntegration:
    """
    Интеграция с CI/CD пайплайнами
    """
    
    async def gitlab_integration(self, project_id: int, gitlab_token: str):
        """
        GitLab CI/CD интеграция
        """
        # .gitlab-ci.yml snippet для клиента
        ci_config = """
security_scan:
  stage: test
  script:
    - |
      SCAN_RESULT=$(curl -X POST https://scanner.example.com/api/scans/unified \
        -H "Authorization: ******" \
        -H "Content-Type: application/json" \
        -d '{
          "target": "$CI_REPOSITORY_URL",
          "scan_type": "repository",
          "options": {"branch": "$CI_COMMIT_REF_NAME"}
        }' | jq -r '.id')
      
      # Дождаться завершения
      while true; do
        STATUS=$(curl -H "Authorization: ******" \
          https://scanner.example.com/api/scans/$SCAN_RESULT/status | jq -r '.status')
        
        if [ "$STATUS" = "done" ]; then
          break
        fi
        sleep 10
      done
      
      # Проверить результаты
      SCORE=$(curl -H "Authorization: ******" \
        https://scanner.example.com/api/scans/$SCAN_RESULT/result | jq -r '.pq_score')
      
      if [ "$SCORE" -gt 60 ]; then
        echo "Security scan failed: PQ-Score = $SCORE"
        exit 1
      fi
  only:
    - merge_requests
"""
        return ci_config
    
    async def github_actions_integration(self):
        """
        GitHub Actions интеграция
        """
        workflow = """
name: Security Scan

on:
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Crypto Scanner
        uses: maxim290905/crypto-scanner-action@v1
        with:
          api_url: ${{ secrets.SCANNER_API_URL }}
          api_token: ${{ secrets.SCANNER_TOKEN }}
          fail_on_score: 60
"""
        return workflow
```

#### Ticket system integration

```python
# backend/app/integrations/ticketing.py
class TicketingIntegration:
    """
    Интеграция с системами тикетов (Jira, ServiceNow)
    """
    
    async def create_jira_ticket(self, finding: dict, jira_config: dict):
        """
        Создать тикет в Jira для finding
        """
        jira = JIRA(
            server=jira_config['server'],
            basic_auth=(jira_config['username'], jira_config['api_token'])
        )
        
        issue_dict = {
            'project': {'key': jira_config['project_key']},
            'summary': f"[Security] {finding['category']} - {finding['title']}",
            'description': self._format_finding_for_jira(finding),
            'issuetype': {'name': 'Bug'},
            'priority': {'name': self._map_severity_to_priority(finding['severity'])},
            'labels': ['security', 'crypto', 'automated'],
        }
        
        new_issue = jira.create_issue(fields=issue_dict)
        return new_issue.key
    
    def _format_finding_for_jira(self, finding: dict) -> str:
        """
        Форматировать finding для Jira
        """
        return f"""
h2. Детали уязвимости

*Категория:* {finding['category']}
*Серьезность:* {finding['severity']}
*Целевой хост:* {finding['target']}

h3. Описание
{finding['description']}

h3. Рекомендации по исправлению
{finding['remediation']}

h3. Ссылки
* [Результаты скана|{finding['scan_url']}]
* [Документация|{finding['doc_url']}]
"""
```

### 3.4. **Machine Learning для предсказаний**

```python
# backend/app/ml/predictor.py
class SecurityPredictor:
    """
    ML-модель для предсказания будущих проблем безопасности
    """
    
    def __init__(self):
        # Загрузить обученную модель
        self.model = self._load_model()
    
    async def predict_future_score(
        self,
        project_id: int,
        days_ahead: int = 30
    ) -> dict:
        """
        Предсказать PQ-Score через N дней
        """
        # Получить исторические данные
        historical_data = await self._get_historical_data(project_id)
        
        # Экстракция признаков
        features = self._extract_features(historical_data)
        
        # Предсказание
        predicted_score = self.model.predict(features)
        
        return {
            'current_score': historical_data[-1]['pq_score'],
            'predicted_score': predicted_score,
            'days_ahead': days_ahead,
            'confidence': 0.85,
            'trend': 'improving' if predicted_score < historical_data[-1]['pq_score'] else 'deteriorating'
        }
    
    async def recommend_actions(self, project_id: int) -> List[dict]:
        """
        Рекомендовать действия на основе ML
        """
        # Анализ паттернов в успешных исправлениях
        successful_remediations = await self._get_successful_remediations()
        
        # Текущие проблемы проекта
        current_issues = await self._get_current_issues(project_id)
        
        # ML рекомендации
        recommendations = self.model.recommend(
            current_issues,
            successful_remediations
        )
        
        return recommendations
```

---

## 🗺️ Implementation Roadmap

### Phase 1: RF Compliance (Q1 2025)
**Приоритет: ВЫСОКИЙ**

- [ ] Модуль ГОСТ детектирования (4 недели)
  - GOST R 34.10-2012 detection
  - GOST R 34.11-2012 detection
  - GOST cipher suites в TLS
- [ ] ФСТЭК compliance checker (3 недели)
  - УЗ-1 до УЗ-4 проверки
  - Запрещенные алгоритмы
- [ ] RF-Score calculation (2 недели)
- [ ] PDF отчеты с RF compliance (2 недели)

**Итого:** 11 недель, 2.5 месяца

### Phase 2: Repository Scanning (Q2 2025)
**Приоритет: ВЫСОКИЙ**

- [ ] Git repository scanner (4 недели)
  - Secret detection
  - Weak crypto patterns
  - Dependency scanning
- [ ] SBOM analysis (3 недели)
  - CycloneDX parser
  - SPDX parser
  - Vulnerability matching
- [ ] Container scanning (4 недели)
  - Docker image analysis
  - Package vulnerability scan

**Итого:** 11 недель, 2.5 месяца

### Phase 3: Business Logic (Q3 2025)
**Приоритет: СРЕДНИЙ**

- [ ] Continuous monitoring (3 недели)
  - Celery Beat scheduling
  - Auto-rescanning
- [ ] Policy engine (4 недели)
  - DSL для политик
  - Action execution
- [ ] Analytics dashboard (4 недели)
  - Trend analysis
  - Historical data
  - ML predictions
- [ ] CI/CD integrations (3 недели)
  - GitLab CI
  - GitHub Actions
  - Jenkins plugin

**Итого:** 14 недель, 3.5 месяца

### Phase 4: Advanced Features (Q4 2025)
**Приоритет: НИЗКИЙ**

- [ ] ML predictor (6 недель)
- [ ] Jira/ServiceNow integration (2 недели)
- [ ] White-label customization (4 недели)
- [ ] Multi-tenancy (4 недели)

**Итого:** 16 недель, 4 месяца

---

## 💰 Бизнес-эффекты от развития

### После Phase 1 (RF Compliance):
- ✅ Выход на рынок госконтрактов РФ (+5M₽ потенциал)
- ✅ Финтех и медтех сектор (+$200k ARR)
- ✅ Конкурентное преимущество: единственный с RF compliance

### После Phase 2 (Repository Scanning):
- ✅ DevSecOps рынок (+$500k ARR)
- ✅ Расширение TAM (Total Addressable Market) в 3x
- ✅ Интеграция в CI/CD пайплайны

### После Phase 3 (Business Logic):
- ✅ Enterprise features → повышение ARPU на 150%
- ✅ Снижение churn rate на 40% (автоматизация)
- ✅ Upsell возможности для существующих клиентов

### После Phase 4 (Advanced):
- ✅ Premium tier pricing (+$100k per customer)
- ✅ White-label партнерства (+$1M ARR)
- ✅ ML competitive moat

---

## 📊 KPI для отслеживания прогресса

### Product KPIs:
- **Scan types supported**: 1 → 5 (domain, repo, container, sbom, binary)
- **RF compliance coverage**: 0% → 100%
- **Average scan time**: < 5 min per asset
- **False positive rate**: < 5%

### Business KPIs:
- **ARR growth**: $200k → $2M (Q1-Q4 2025)
- **Customer acquisition**: 5 → 50 paying customers
- **Market share**: 0% → 5% (Russian PQC market)
- **NPS score**: > 50

### Technical KPIs:
- **API uptime**: > 99.5%
- **Scan success rate**: > 95%
- **Code coverage**: > 80%
- **Security vulnerabilities**: 0 critical, < 5 high

---

## 🎯 Выводы и рекомендации

### Главные приоритеты:

1. **RF Compliance (Q1)** - критично для российского рынка
   - Госконтракты требуют соответствия ФСТЭК/ФСБ
   - Быстрая окупаемость через крупные контракты

2. **Repository Scanning (Q2)** - расширение TAM
   - DevSecOps рынок огромен ($15B+)
   - Интеграция в существующие процессы разработки

3. **Business Logic (Q3)** - увеличение retention
   - Автоматизация снижает churn
   - Enterprise features повышают ARPU

4. **Advanced Features (Q4)** - конкурентный барьер
   - ML создает технологический moat
   - White-label открывает B2B2C канал

### Ресурсы:
- **Команда**: 3-4 разработчика на 12 месяцев
- **Бюджет**: $300k-400k (зарплаты + инфраструктура)
- **ROI**: $2M+ ARR к концу 2025 = 5-7x ROI

### Риски:
- ⚠️ Сертификация ФСТЭК может занять 6+ месяцев
- ⚠️ Сложность интеграции с ГОСТ криптографией
- ⚠️ Конкуренция с западными вендорами на репо-сканировании

### Митигация:
- ✅ Начать сертификацию параллельно с разработкой
- ✅ Партнерство с CryptoPro/ViPNet для ГОСТ
- ✅ Фокус на российский рынок (импортозамещение)

---

**Итоговая оценка**: Все три направления развития критически важны и обеспечат проекту **лидирующую позицию** на рынке криптографического аудита в России к концу 2025 года.
