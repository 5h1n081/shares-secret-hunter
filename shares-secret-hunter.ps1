param (
    [Parameter(Mandatory=$true)]
    [string]$NetworkPath,
    [string]$OutputFile = ".\scan_results.txt",
    [int]$MaxDepth = 10,
    [int]$MaxThreads = 10,
    [string[]]$ExcludeDirs = @('Windows', 'Program Files', 'Program Files (x86)', '$Recycle.Bin'),
    [string[]]$FileExtensions = @(
        # конфиги
        '.config', '.conf', '.cfg', '.ini', '.env', '.yml', '.yaml', '.properties', '.props', '.prefs',
        '.xml', '.json', '.toml', '.cnf', '.inf', '.reg', '.settings', '.option', '.plist',
        
        # скрипты и тд
        '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.sh', '.bash', '.ksh', '.zsh', '.fish',
        '.py', '.pyc', '.pyo', '.pyw', '.rb', '.rbw', '.php', '.php3', '.php4', '.php5', '.phtml',
        '.pl', '.pm', '.t', '.pod', '.js', '.jsx', '.ts', '.tsx', '.coffee', '.cs', '.vb',
        '.asp', '.aspx', '.jsp', '.jspx', '.cshtml', '.vbhtml',
        
        # текстовые файлы
        '.txt', '.log', '.text', '.md', '.markdown', '.rst', '.rtf', '.doc', '.docx',
        '.csv', '.tsv', '.dat', '.lst', '.list',
        
        # бд
        '.sql', '.sqlite', '.sqlite3', '.db', '.mdb', '.accdb', '.dbf', '.odb',
        
        # ключи и серты
        '.pem', '.key', '.pkcs12', '.pfx', '.p12', '.der', '.csr', '.crt', '.cer', '.p7b',
        '.keystore', '.jks', '.truststore', '.ppk', '.asc',
        
        # архив4ики и бэкап4ики
        '.bak', '.backup', '.old', '.orig', '.temp', '.tmp',
        '.save', '.sav', '.back', '.bck', '.swp',
        
        # специфичные расширения
        '.htaccess', '.htpasswd', '.npmrc', '.yarnrc', '.env.local', '.env.dev',
        '.env.development', '.env.prod', '.env.production', '.env.test',
        '.git-credentials', '.docker', '.dockerignore', 'dockerfile',
        '.kube', '.kubeconfig', '.helm', '.terraform', '.tfvars',
        
        # IDE и редакторы
        '.vscode', '.idea', '.project', '.classpath', '.iml', '.sublime-project',
        '.sublime-workspace', '.editorconfig',
        
        # специфичные файлы винды
        '.rdp', '.remmina', '.vnc', '.ssh', '.telnet',
        
        # специфичные файлы для веба
        '.htaccess', '.htpasswd', '.conf.inc', '.config.inc',
        '.inc.php', '.inc', '.dist',
        
        # файлы с потенциальными секретами
        '.credentials', '.secret', '.password', '.token', '.oauth',
        '.aws', '.azure', '.gcp', '.kube', '.ssh', '.gnupg', '.pgp',
        
        # архив4ики
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.tgz', '.tbz2', '.txz', '.iso', '.cab', '.jar'
    )
)

$asciiArt = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ███████╗██╗  ██╗ █████╗ ██████╗ ███████╗███████╗                         ║
║    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝                         ║
║    ███████╗███████║███████║██████╔╝█████╗  ███████╗                         ║
║    ╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝  ╚════██║                         ║
║    ███████║██║  ██║██║  ██║██║  ██║███████╗███████║                         ║
║    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝                         ║
║                                                                              ║
║    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗                        ║
║    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝                        ║
║    ███████╗█████╗  ██║     ██████╔╝█████╗     ██║                           ║
║    ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║                           ║
║    ███████║███████╗╚██████╗██║  ██║███████╗   ██║                           ║
║    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                           ║
║                                                                              ║
║    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗                     ║
║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗                    ║
║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝                    ║
║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗                    ║
║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║                    ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                    ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  [ Shares Secret Hunter v1.0 ]            [ Last Updated: $(Get-Date -Format "yyyy-MM-dd") ] ║
║  [ Created by: 5h1n081 ]                  [ Secure Your Network ]           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@

Write-Host $asciiArt -ForegroundColor Cyan

# классификация секретов по уровню критичности
$sensitivityLevels = @{
    'Critical' = @(
        'AWS Access Key ID', 'AWS Secret Key', 'Private Key', 'SSH Private Key',
        'Credit Card', 'Azure Storage Key', 'GitHub Token',
        'Mattermost Token', 'YooKassa Live Token', 'Yandex Cloud IAM',
        'Tinkoff API Token', 'Sberbank API Token', 'WebMoney API Key', 'QIWI Token',
        'VMware API Token', 'Elasticsearch Token', 'Splunk Token', 'Ansible Vault Password',
        'Veeam Token', 'Cisco CallManager Token', '1C Doc Token',
        'Hikvision API Token', 'Dahua API Token', 'Trassir Token', 'Macroscop Token', 'Axxon Token',
        'Bitcoin Private Key', 'Ethereum Private Key', 'Metamask Seed Phrase', 'Binance API Secret',
        'Huobi API Secret', 'Bybit API Secret',
        'OpenVPN Private Key',
        'IPSec PSK',
        'WireGuard Private Key',
        'Cisco AnyConnect Key',
        'FortiClient VPN Key'
    )
    'High' = @(
        'Password', 'API Key', 'Bearer Token', 'Database Connection', 'Certificate',
        'Stripe Key', 'PayPal Token', 'JWT Token', 'Yandex OAuth Token',
        'Yandex API Key', 'YooKassa Test Token', 'Yandex Metrika Token',
        'VK API Token', 'Bitrix Token', 'Mail.ru OAuth Token', 'OK OAuth Token',
        'Wildberries API Key', 'OZON API Key', 'DaData API Token',
        'Zabbix API Token', 'Grafana API Key', 'Kibana Token', 'Puppet Token',
        'Proxmox Token', 'Asterisk Key', 'FreePBX Token', 'Yeastar Token',
        '3CX Token',
        'Milestone Token', 'Pelco API Token'
    )
    'Medium' = @(
        'Generic Secret', 'Email Password', 'Domain Password', 'IP Address',
        'Authorization Header', 'Firebase URL',
        'RuTube API Token', 'Beeline API Token', 'MegaFon API Token', 'MTS API Token',
        'CDEK API Token', '2GIS API Key',
        'Nagios API Key', 'Graylog Token', 'Chef Key', 'Hyper-V Key', 'Bacula Key',
        'Commvault Token', 'Asterisk SIP Password', 'TEZIS Token', 'TEZIS API Key',
        'DocsVision License', '1C License Key'
    )
    'Low' = @(
        'Generic Token', 'Public Key', 'SSH Public Key'
    )
}

# паттерны для поиска секретов
$sensitivePatterns = @{
    # пароли и учетки
    'Password' = '(?i)(password|pwd|passwd|credentials)[=:"\s].{0,30}'
    'Basic Auth' = 'Basic [a-zA-Z0-9+/=]{20,}'
    'Bearer Token' = 'Bearer [a-zA-Z0-9._-]{20,}'
    'Authorization Header' = '(?i)Authorization:\s*[a-zA-Z0-9+/=_-]{20,}'
    'Generic Secret' = '(?i)(secret|token|key|auth|pass)[=:"\s].{0,50}'
    
    # API ключи и токены
    'API Key' = '(?i)(api[_-]?key|api[_-]?secret|access[_-]?key|auth[_-]?token)[=:"\s].{0,50}'
    'Generic Token' = '(?i)(token|secret|key)[=:"\s][a-zA-Z0-9._-]{20,}'
    'JWT Token' = 'eyJ[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_.+/=]+'
    
    # AWS
    'AWS Access Key ID' = '(?i)AKIA[0-9A-Z]{16}'
    'AWS Secret Key' = '(?i)[0-9a-zA-Z/+]{40}'
    'AWS Session Token' = '(?i)FQoG[A-Za-z0-9/+=]{200,}'
    'AWS MWS Key' = 'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    
    # Azure
    'Azure Storage Key' = '(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'
    'Azure Connection String' = '(?i)Server=tcp:[^;]+;Database=[^;]+;User ID=[^;]+;Password=[^;]+'
    'Azure SAS Token' = '(?i)sv=\d{4}-\d{2}-\d{2}&s[ist]=.*&s[ipurt]=.*&sp=.*'
    'Azure AD Client Secret' = '(?i)[a-zA-Z0-9-]{36}|[a-zA-Z0-9-]{32}'
    
    # Google Cloud
    'Google API Key' = 'AIza[0-9A-Za-z\-_]{35}'
    'Google OAuth' = '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'
    'Google Service Account' = '(?i)"type": "service_account"'
    'Firebase URL' = '(?i)firebaseio\.com'
    
    # GitHub
    'GitHub Token' = '(?i)gh[pousr]_[0-9a-zA-Z]{36}'
    'GitHub OAuth' = '(?i)gho_[0-9a-zA-Z]{36}'
    'GitHub App Token' = '(?i)(ghu|ghs)_[0-9a-zA-Z]{36}'
    'GitHub Refresh Token' = '(?i)ghr_[0-9a-zA-Z]{76}'
    
    # GitLab
    'GitLab Token' = '(?i)glpat-[0-9a-zA-Z\-\_]{20}'
    'GitLab Runner Token' = '(?i)glrt-[0-9a-zA-Z\-\_]{20}'
    'GitLab OAuth' = '(?i)gitlab-oauth[0-9a-zA-Z\-\_]{20}'
    
    # коннекты к бд
    'MySQL Connection' = '(?i)mysql:\/\/[^:]+:[^@]+@.+'
    'PostgreSQL Connection' = '(?i)postgres(ql)?:\/\/[^:]+:[^@]+@.+'
    'MongoDB URI' = 'mongodb(\+srv)?:\/\/[^:]+:[^@]+@.+'
    'Redis Connection' = '(?i)redis:\/\/[^:]+:[^@]+@.+'
    'Oracle Connection' = '(?i)oracle:\/\/[^:]+:[^@]+@.+'
    'MSSQL Connection' = '(?i)(Server|Data Source)=[^;]+;(Initial Catalog|Database)=[^;]+;User ID=[^;]+;Password=[^;]+'
    
    # приватные ключи и серты
    'Private Key' = '-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY( BLOCK)?-----'
    'PGP Private Key' = '-----BEGIN PGP PRIVATE KEY BLOCK-----'
    'SSH Private Key' = '-----BEGIN OPENSSH PRIVATE KEY-----'
    'Certificate' = '-----BEGIN CERTIFICATE-----'
    'SSH Public Key' = 'ssh-rsa [A-Za-z0-9+/]+[=]{0,3}'
    
    # платежки
    'Stripe Key' = '(?i)(pk|sk|rk)_(live|test)_[0-9a-zA-Z]{24,}'
    'Stripe Webhook' = '(?i)whsec_[0-9a-zA-Z]{32}'
    'PayPal Token' = '(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
    'Square Access Token' = 'sq0atp-[0-9A-Za-z\-_]{22}'
    'Square OAuth Token' = 'sq0csp-[0-9A-Za-z\-_]{43}'
    'Braintree Access Token' = 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
    
    # мессенджеры
    'Slack Token' = '(?i)xox[baprs]-([0-9a-zA-Z]{10,48})'
    'Slack Webhook' = 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
    'Discord Webhook' = 'https://discord\.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]{68}'
    'Telegram Bot Token' = '[0-9]{8,10}:[a-zA-Z0-9_-]{35}'
    'Mattermost Token' = '(?i)(xox[p|b|s|r|g|a]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}|[a-z0-9]{26})'
    'Mattermost Webhook' = 'https?://[^/]+/hooks/[a-zA-Z0-9]{26}'
    
    # чувствительные данные
    'Credit Card' = '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
    'Email Password' = '(?i)(smtp|imap|pop3).*[=:].+'
    'IP Address' = '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    'Domain Password' = '(?i)(domain|ad|ldap).*password.*[=:].+'
    
    # прочее
    'MailChimp API Key' = '[0-9a-f]{32}-us[0-9]{1,2}'
    'MailGun API Key' = 'key-[0-9a-zA-Z]{32}'
    'NPM Token' = '(?i)npm_[a-z0-9]{36}'
    'CircleCI Token' = '(?i)circle.*[a-z0-9]{40}'
    'Twilio API Key' = 'SK[0-9a-fA-F]{32}'
    'Jenkins Creds' = '(?i)[\w-]*password[\w-]*["\']?\s*[:=]\s*["\']?[^"\'\n]+'
    
    # Яндекс
    'Yandex OAuth Token' = 'y0_AgAAAAA[a-zA-Z0-9_-]{38}'
    'Yandex API Key' = 'AQVN[a-zA-Z0-9_-]{32}'
    'YooKassa Live Token' = 'live_[a-zA-Z0-9_-]{52,54}'
    'YooKassa Test Token' = 'test_[a-zA-Z0-9_-]{52,54}'
    'Yandex Metrika Token' = '(?i)(metrika|metrica).{0,10}[a-f0-9]{32}'
    'Yandex Cloud IAM' = '(?i)t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}'
    
    # вконтактич
    'VK API Token' = '(?i)vk1\.[a-zA-Z0-9]{85}'
    'VK Service Token' = '(?i)vk1\.as\.[0-9a-f]{85}'
    'VK Community Token' = '(?i)(vk1\.a\.[a-zA-Z0-9_-]{60,}|access_token=[a-zA-Z0-9]{85})'
    
    # битрикс
    'Bitrix Token' = '(?i)(\.{3}|[a-z0-9]{32})'
    'Bitrix Webhook' = 'https?://[^/]+/rest/[0-9]+/[a-zA-Z0-9]{32}/'
    
    # киви
    'Qiwi Token' = '(?i)[a-f0-9]{32}'
    'Qiwi Secret Key' = '(?i)eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
    
    # т-банк
    'Tinkoff API Token' = 'T[a-zA-Z0-9]{35,}'
    'Tinkoff OAuth Token' = 'TinkoffOpenApiSandbox|TinkoffOpenApi'
    
    # сбер
    'Sberbank API Token' = '(?i)[a-f0-9]{32}'
    'Sberbank OAuth Token' = '(?i)t.[0-9a-zA-Z-]+.[0-9a-zA-Z-]+'
    
    # рутуб
    'RuTube API Token' = 'rt[0-9a-f]{32}'
    
    # mail.ru
    'Mail.ru OAuth Token' = '(?i)(mail|mrg)_[0-9a-f]{32}'
    'Mail.ru Secret Key' = '(?i)[0-9a-f]{32}'
    
    # одноклы 
    'OK OAuth Token' = 'tk[A-Z0-9]{15,}'
    'OK Access Token' = '(?i)ok_access_token=[a-f0-9]{32}'
    
    # webmoney
    'WebMoney API Key' = '[A-F0-9]{32}'
    'WebMoney Signature' = '[A-F0-9]{132,}'
    
    # опрераторы
    'Beeline API Token' = 'beeline_[a-zA-Z0-9]{32}'
    'MegaFon API Token' = 'mgf_[a-zA-Z0-9]{32}'
    'MTS API Token' = 'mts_[a-zA-Z0-9]{32}'
    
    # доставка
    'Avito API Token' = 'af[0-9]{10,}_[a-zA-Z0-9]{32}'
    'CDEK API Token' = 'EMscd\.[0-9]{8}\.[a-zA-Z0-9-_]+'
    'DaData API Token' = '[0-9a-f]{40}'
    'DaData Secret Key' = '[0-9a-f]{40}'
    
    # антивири 
    'Kaspersky Token' = 'KL[a-zA-Z0-9-_]{32,}'
    'DrWeb Token' = 'DW[a-zA-Z0-9]{32}'
    
    # 2гис
    '2GIS API Key' = 'ru[a-zA-Z0-9]{36,}'
    
    # вайлдберрис
    'Wildberries API Key' = '[a-zA-Z0-9]{48}'
    'Wildberries Token' = '(?i)(standard|statistics|adv|content|analytics)_[a-zA-Z0-9]{48}'
    
    # озон
    'OZON API Key' = '[a-f0-9]{32}'
    'OZON Client ID' = '[0-9]{6,8}'
    
    # мониторинг
    'Zabbix API Token' = '(?i)[a-f0-9]{32,}'
    'Zabbix Auth Token' = '(?i)zbx_sessionid=[a-f0-9]{16}'
    'Nagios API Key' = '(?i)nagios_[a-zA-Z0-9]{32}'
    'Grafana API Key' = '(?i)eyJrIjoi[A-Za-z0-9-_=]{32,}'
    'Prometheus Token' = '(?i)prom[_-]?token[_-]?[a-zA-Z0-9]{32}'
    
    # системы логирования
    'Elasticsearch Token' = '(?i)(elastic|es)_[a-zA-Z0-9]{32}'
    'Kibana Token' = '(?i)kibana_[a-zA-Z0-9]{32}'
    'Logstash Key' = '(?i)logstash_[a-zA-Z0-9]{32}'
    'Graylog Token' = '(?i)graylog_[a-zA-Z0-9]{64}'
    'Splunk Token' = '(?i)(splunk|splk)_[a-zA-Z0-9]{32}'
    
    # автоматизация
    'Ansible Vault Password' = '(?i)ANSIBLE_VAULT;[0-9]\.[0-9];AES256'
    'Ansible Token' = '(?i)ansible[_-]token[_-][a-zA-Z0-9]{32}'
    'Puppet Token' = '(?i)puppet[_-]token[_-][a-zA-Z0-9]{32}'
    'Chef Key' = '(?i)chef[_-]key[_-][a-zA-Z0-9]{32}'
    'SaltStack Token' = '(?i)salt[_-]token[_-][a-zA-Z0-9]{32}'
    
    # виртуалки
    'VMware API Token' = '(?i)vmware[_-]api[_-][a-zA-Z0-9]{32}'
    'VMware Session ID' = '(?i)vmware_session_id=[a-f0-9]{32}'
    'Hyper-V Key' = '(?i)hyperv[_-]key[_-][a-zA-Z0-9]{32}'
    'Proxmox Token' = 'PVEAPIToken=[a-zA-Z0-9]{64}'
    'XenServer Key' = '(?i)xen[_-]api[_-][a-zA-Z0-9]{32}'
    
    # бэкап4ики
    'Veeam Token' = '(?i)veeam[_-]token[_-][a-zA-Z0-9]{32}'
    'Acronis Token' = '(?i)acronis[_-]token[_-][a-zA-Z0-9]{32}'
    'Bacula Key' = '(?i)bacula[_-]key[_-][a-zA-Z0-9]{32}'
    'Commvault Token' = '(?i)commvault[_-]token[_-][a-zA-Z0-9]{32}'
    
    # IP-телефония
    'Asterisk Key' = '(?i)(secret|password|key)[=:"\s][a-zA-Z0-9]{32}'
    'Asterisk SIP Password' = '(?i)secret\s*=\s*[a-zA-Z0-9._-]{8,}'
    'FreePBX Token' = '(?i)freepbx[_-]token[_-][a-zA-Z0-9]{32}'
    'FreePBX Admin Hash' = '(?i)[a-f0-9]{32}:(?:[a-f0-9]{32}|ampuser)'
    'Cisco CallManager Token' = '(?i)cucm[_-][a-zA-Z0-9]{32}'
    'Cisco UCM Token' = '(?i)Bearer [a-zA-Z0-9-._]{100,}'
    'Yeastar Token' = '(?i)yeastar[_-]api[_-][a-zA-Z0-9]{32}'
    '3CX Token' = '(?i)3cx[_-]token[_-][a-zA-Z0-9]{32}'
    '3CX License Key' = '(?i)3CXPBX-[A-Z0-9]{16}'
    
    # СЭДы
    '1C Doc Token' = '(?i)1cdoc[_-]token[_-][a-zA-Z0-9]{32}'
    '1C License Key' = '(?i)[0-9]{10,15}:[A-Z0-9]{10}'
    'TEZIS Token' = '(?i)tezis[_-]token[_-][a-zA-Z0-9]{32}'
    'TEZIS API Key' = '(?i)tezis[_-]api[_-][a-zA-Z0-9]{32}'
    
    # камеры
    'Hikvision API Token' = '(?i)(hik|hikvision)[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Hikvision Digest Auth' = '(?i)digest\s+username="[^"]+",\s*realm="[^"]+",\s*nonce="[^"]+"'
    'Hikvision Session' = '(?i)JSESSIONID=[A-F0-9]{32}'
    
    'Dahua API Token' = '(?i)(dh|dahua)[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Dahua Session ID' = '(?i)DhWebClientSessionID=[a-zA-Z0-9]{32}'
    'Dahua Auth Token' = '(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{20,}'
    
    'Trassir Token' = '(?i)trassir[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Trassir SDK Key' = '(?i)sdk[_-]?key[_-]?[a-zA-Z0-9]{32}'
    'Trassir Cloud Token' = '(?i)cloud[_-]?token[_-]?[a-zA-Z0-9]{64}'
    
    'Macroscop Token' = '(?i)macroscop[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Macroscop License' = '(?i)ms[_-]?lic[_-]?[a-zA-Z0-9]{16}'
    'Macroscop API Key' = '(?i)ms[_-]?api[_-]?[a-zA-Z0-9]{32}'
    
    'Axxon Token' = '(?i)axxon[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Axxon License Key' = '(?i)nx[_-]?lic[_-]?[a-zA-Z0-9]{32}'
    'Axxon Session ID' = '(?i)NXSESSIONID=[a-zA-Z0-9]{32}'
    
    'Milestone Token' = '(?i)milestone[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Milestone API Key' = '(?i)xprotect[_-]?api[_-]?[a-zA-Z0-9]{32}'
    'Milestone License' = '(?i)mlk[_-]?[a-zA-Z0-9]{32}'
    
    'Pelco API Token' = '(?i)pelco[_-]?token[_-]?[a-zA-Z0-9]{32}'
    'Pelco Session ID' = '(?i)PELCOSESSIONID=[a-zA-Z0-9]{32}'
    'Pelco License Key' = '(?i)plk[_-]?[a-zA-Z0-9]{32}'
    
    # крипта
    'Bitcoin Private Key' = '([5KL][1-9A-HJ-NP-Za-km-z]{50,51}|[cC][1-9A-HJ-NP-Za-km-z]{50,51}|[1-9A-HJ-NP-Za-km-z]{52})'
    'Bitcoin Address' = '([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})'
    'Bitcoin WIF' = '([5KL][1-9A-HJ-NP-Za-km-z]{50,51})'
    
    'Ethereum Private Key' = '([0-9a-fA-F]{64}|0x[0-9a-fA-F]{64})'
    'Ethereum Address' = '0x[a-fA-F0-9]{40}'
    'Ethereum Seed Phrase' = '(?i)(?:\b\w+\b\s+){11,23}\b\w+\b'
    
    'Metamask Seed Phrase' = '(?i)(?:\b\w+\b\s+){11,23}\b\w+\b'
    'Metamask Private Key' = '0x[0-9a-fA-F]{64}'
    'Metamask Wallet' = '0x[a-fA-F0-9]{40}'
    
    'Binance API Key' = '[a-zA-Z0-9]{64}'
    'Binance API Secret' = '[a-zA-Z0-9]{64}'
    'Binance Wallet' = 'bnb[a-zA-Z0-9]{39}'
    
    'Huobi API Key' = '(?i)[0-9a-f]{32}'
    'Huobi API Secret' = '(?i)[0-9a-f]{64}'
    'Huobi Access Token' = '(?i)huobi[_-]token[_-][a-zA-Z0-9]{32}'
    
    'Bybit API Key' = '[a-zA-Z0-9]{18,24}'
    'Bybit API Secret' = '[a-zA-Z0-9]{36}'
    'Bybit Access Token' = '(?i)bybit[_-]token[_-][a-zA-Z0-9]{32}'
    
    'Crypto.com API Key' = '(?i)[a-z0-9]{32}'
    'Crypto.com API Secret' = '(?i)[a-z0-9]{64}'
    
    'KuCoin API Key' = '(?i)[a-f0-9]{24}'
    'KuCoin API Secret' = '(?i)[a-f0-9]{36}'
    
    'Kraken API Key' = '(?i)[a-z0-9]{32}'
    'Kraken API Secret' = '(?i)[a-z0-9]{64}'
    
    'Poloniex API Key' = '(?i)[a-z0-9]{32}'
    'Poloniex API Secret' = '(?i)[a-z0-9]{64}'
    
    # впн
    'OpenVPN Private Key' = '-----BEGIN PRIVATE KEY-----[a-zA-Z0-9/+\s]+-----END PRIVATE KEY-----'
    'OpenVPN Certificate' = '-----BEGIN CERTIFICATE-----[a-zA-Z0-9/+\s]+-----END CERTIFICATE-----'
    'OpenVPN Static Key' = '-----BEGIN OpenVPN Static key V1-----[a-zA-Z0-9/+\s]+-----END OpenVPN Static key V1-----'
    'OpenVPN TLS Auth' = '-----BEGIN OpenVPN tls-auth-----[a-zA-Z0-9/+\s]+-----END OpenVPN tls-auth-----'
    
    'IPSec PSK' = '(?i)(PSK|shared secret|IKE key)[=:"\s].{8,}'
    'IPSec XAUTH' = '(?i)(xauth-?password)[=:"\s].{8,}'
    'IPSec Group Password' = '(?i)(group-?password)[=:"\s].{8,}'
    
    'WireGuard Private Key' = '[a-zA-Z0-9+/]{43}='
    'WireGuard Public Key' = '[a-zA-Z0-9+/]{43}='
    'WireGuard Preshared Key' = '[a-zA-Z0-9+/]{43}='
    
    'Cisco AnyConnect Key' = '(?i)(anyconnect|vpn)[-_]?(password|key|secret)[=:"\s].{8,}'
    'Cisco AnyConnect Profile' = '(?i)<AnyConnectProfile>.+</AnyConnectProfile>'
    'Cisco AnyConnect CSD' = '(?i)(csd[-_]?wrapper|hostscan[-_]?token)[=:"\s].+'
    
    'FortiClient VPN Key' = '(?i)(forticlient|fortinet)[-_]?(password|key|secret)[=:"\s].{8,}'
    'FortiClient SSL VPN' = '(?i)(sslvpn|fortissl)[-_]?(password|key|secret)[=:"\s].{8,}'
    'FortiClient Config' = '(?i)<forticlient_configuration>.+</forticlient_configuration>'
    
    'PPTP Password' = '(?i)(PPTP|MPPE)[-_]?(password|key|secret)[=:"\s].{8,}'
    'L2TP Secret' = '(?i)(L2TP|IPSec)[-_]?(password|key|secret)[=:"\s].{8,}'
    'SSTP Key' = '(?i)(SSTP|MS-SSTP)[-_]?(password|key|secret)[=:"\s].{8,}'
    
    'GlobalProtect Portal' = '(?i)(portal-userauthcookie|portal-prelogonuserauthcookie)[=:"\s].+'
    'GlobalProtect Gateway' = '(?i)(gateway-userauthcookie|gateway-prelogonuserauthcookie)[=:"\s].+'
    
    'Pulse Secure VPN' = '(?i)(pulse|juniper)[-_]?(password|key|secret)[=:"\s].{8,}'
    'Pulse Secure Cookie' = 'DSID=[a-f0-9]{32}'
    
    'CheckPoint VPN' = '(?i)(checkpoint|vpn)[-_]?(password|key|secret)[=:"\s].{8,}'
    'CheckPoint Certificate' = '(?i)(usercertificate|p12file)[=:"\s].+'
}

# статистика в синхронизированный хэш
$script:syncHash = [hashtable]::Synchronized(@{
    Results = [System.Collections.ArrayList]::new()
    ProcessedFiles = 0
    TotalFiles = 0
    RunspacePool = $null
    Statistics = @{
        StartTime = Get-Date
        TotalDirectories = 0
        TotalFiles = 0
        ProcessedFiles = 0
        SkippedFiles = 0
        ArchivedFiles = 0
        ErrorCount = 0
        SecretsFound = 0
        FileTypes = @{}
        SecretTypes = @{}
        CriticalityLevels = @{
            Critical = 0
            High = 0
            Medium = 0
            Low = 0
        }
        ProcessingTime = @{
            ScanTime = 0
            ArchiveExtractionTime = 0
            FileAnalysisTime = 0
        }
        LargestFiles = @()
        TopDirectories = @{}
    }
})

# создание пула потоков
function Initialize-ThreadPool {
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    
    # импорт необходимых функций в сессию
    $sessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'sensitivePatterns', $sensitivePatterns, ''))
    $sessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'sensitivityLevels', $sensitivityLevels, ''))
    
    $script:syncHash.RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $Host)
    $script:syncHash.RunspacePool.Open()
}

# обработка файла в отдельном потоке
function Start-FileProcessing {
    param (
        [string]$FilePath,
        [string]$FileExtension
    )
    
    $powershell = [powershell]::Create().AddScript({
        param($FilePath, $FileExtension, $syncHash)
        
        # импорт функций в поток
        function Find-Secrets {
            param([string]$FilePath)
            try {
                $content = Get-Content $FilePath -Raw -ErrorAction Stop
                $findings = @()
                
                foreach ($pattern in $sensitivePatterns.GetEnumerator()) {
                    if ($content -match $pattern.Value) {
                        $match = $matches[0]
                        $lineNumber = ($content -split "`n").FindIndex({ $_ -match [regex]::Escape($match) }) + 1
                        
                        $findings += @{
                            Type = $pattern.Key
                            Match = $match
                            File = $FilePath
                            Line = $lineNumber
                        }
                    }
                }
                return $findings
            }
            catch {
                Write-Error "Error reading file $FilePath : $_"
                return $null
            }
        }
        
        # обработка файла
        if ($FileExtension -match '\.(zip|rar|7z|gz|tgz)$') {
            $tempPath = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
            New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
            
            try {
                switch -Regex ($FileExtension) {
                    '\.zip$' { Expand-Archive -Path $FilePath -DestinationPath $tempPath -Force }
                    '\.(gz|tgz|rar|7z)$' { & 7z x $FilePath "-o$tempPath" -y | Out-Null }
                }
                
                Get-ChildItem -Path $tempPath -Recurse -File | ForEach-Object {
                    $secrets = Find-Secrets -FilePath $_.FullName
                    if ($secrets) {
                        foreach ($secret in $secrets) {
                            $syncHash.Results.Add($secret) | Out-Null
                        }
                    }
                }
            }
            finally {
                Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            $secrets = Find-Secrets -FilePath $FilePath
            if ($secrets) {
                foreach ($secret in $secrets) {
                    $syncHash.Results.Add($secret) | Out-Null
                }
            }
        }
        
        # увеличение счетчика обработанных файлов
        $syncHash.ProcessedFiles++
        
    }).AddArgument($FilePath).AddArgument($FileExtension).AddArgument($script:syncHash)
    
    $powershell.RunspacePool = $script:syncHash.RunspacePool
    
    return @{
        PowerShell = $powershell
        Handle = $powershell.BeginInvoke()
    }
}

# модифицированная функция сканирования с многопоточностью
function Scan-Directory {
    param (
        [string]$Path,
        [int]$CurrentDepth = 0
    )
    
    if ($CurrentDepth -gt $MaxDepth) { return }
    
    try {
        $jobs = @()
        $files = Get-ChildItem -Path $Path -File -ErrorAction Stop |
                Where-Object { $_.Extension -in $FileExtensions }
        
        $script:syncHash.TotalFiles += $files.Count
        
        foreach ($file in $files) {
            $jobs += Start-FileProcessing -FilePath $file.FullName -FileExtension $file.Extension
        }
        
        # рекурсивное сканирование поддиректорий
        Get-ChildItem -Path $Path -Directory -ErrorAction Stop |
            Where-Object { $ExcludeDirs -notcontains $_.Name } |
            ForEach-Object {
                Scan-Directory -Path $_.FullName -CurrentDepth ($CurrentDepth + 1)
            }
        
        # ожидание завершения всех задач
        while ($jobs.Handle.IsCompleted -contains $false) {
            Write-ProgressBar -Current $script:syncHash.ProcessedFiles -Total $script:syncHash.TotalFiles
            Start-Sleep -Milliseconds 100
        }
        
        # очистка ресурсов
        foreach ($job in $jobs) {
            $job.PowerShell.EndInvoke($job.Handle)
            $job.PowerShell.Dispose()
        }
    }
    catch {
        Write-Host "Error accessing $Path : $_" -ForegroundColor Red
    }
}

# основная логика скрипта
try {
    $startTime = Get-Date
    Initialize-ThreadPool
    
    Write-Host "`nStarting scan of $NetworkPath..." -ForegroundColor Green
    
    if (Test-Path $NetworkPath) {
        Scan-Directory -Path $NetworkPath
    }
    else {
        Write-Host "Error: Path $NetworkPath is not accessible" -ForegroundColor Red
        exit
    }
}
finally {
    # закрытие пула потоков
    if ($script:syncHash.RunspacePool) {
        $script:syncHash.RunspacePool.Close()
        $script:syncHash.RunspacePool.Dispose()
    }
}

# генерирование отчета из синхронизированных результатов
$results = $script:syncHash.Results.ToArray()

# генерим отчет
$duration = (Get-Date) - $startTime
$summary = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                 Scan Summary                                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
  Scan completed: $(Get-Date)
  Duration: $($duration.ToString('hh\:mm\:ss'))
  Total secrets found: $($results.Count)
  
Findings by type:
$($results | Group-Object Type | ForEach-Object { "  $($_.Name): $($_.Count)" } | Out-String)
╚══════════════════════════════════════════════════════════════════════════════╝

Detailed findings:
"@

# модификация формат отчета для включения критичности
$results | ForEach-Object {
    $summary += @"

Type: $($_.Type)
Criticality: $($_.Criticality)
File: $($_.File)
Line: $($_.Line)
Match: $($_.Match)
-------------------
"@
}

# сохранение результатов
$summary | Out-File $OutputFile

Write-Host "`nScan completed!" -ForegroundColor Green
Write-Host "Results saved to: $OutputFile" -ForegroundColor Yellow
Write-Host $summary 

# функция для обновления статистики
function Update-Statistics {
    param (
        [string]$StatType,
        [object]$Data
    )
    
    switch ($StatType) {
        'FileProcessed' {
            $script:syncHash.Statistics.ProcessedFiles++
            $extension = [System.IO.Path]::GetExtension($Data)
            if (-not $script:syncHash.Statistics.FileTypes.ContainsKey($extension)) {
                $script:syncHash.Statistics.FileTypes[$extension] = 0
            }
            $script:syncHash.Statistics.FileTypes[$extension]++
        }
        'SecretFound' {
            $script:syncHash.Statistics.SecretsFound++
            if (-not $script:syncHash.Statistics.SecretTypes.ContainsKey($Data.Type)) {
                $script:syncHash.Statistics.SecretTypes[$Data.Type] = 0
            }
            $script:syncHash.Statistics.SecretTypes[$Data.Type]++
            $script:syncHash.Statistics.CriticalityLevels[$Data.Criticality]++
        }
        'DirectoryProcessed' {
            $script:syncHash.Statistics.TotalDirectories++
            if (-not $script:syncHash.Statistics.TopDirectories.ContainsKey($Data)) {
                $script:syncHash.Statistics.TopDirectories[$Data] = 0
            }
            $script:syncHash.Statistics.TopDirectories[$Data]++
        }
        'Error' {
            $script:syncHash.Statistics.ErrorCount++
        }
        'ArchiveProcessed' {
            $script:syncHash.Statistics.ArchivedFiles++
        }
        'FileSkipped' {
            $script:syncHash.Statistics.SkippedFiles++
        }
    }
}

# модификация функции генерации отчета
function Generate-StatisticsReport {
    $stats = $script:syncHash.Statistics
    $endTime = Get-Date
    $totalTime = $endTime - $stats.StartTime
    
    $statisticsReport = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                              Scanning Statistics                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
  Scan Duration: $($totalTime.ToString('hh\:mm\:ss'))
  
  Files Statistics:
  ---------------
  Total Directories Scanned: $($stats.TotalDirectories)
  Total Files Scanned: $($stats.ProcessedFiles)
  Skipped Files: $($stats.SkippedFiles)
  Archives Processed: $($stats.ArchivedFiles)
  Errors Encountered: $($stats.ErrorCount)
  
  Secrets Found:
  -------------
  Total Secrets: $($stats.SecretsFound)
  By Criticality:
    Critical: $($stats.CriticalityLevels.Critical)
    High: $($stats.CriticalityLevels.High)
    Medium: $($stats.CriticalityLevels.Medium)
    Low: $($stats.CriticalityLevels.Low)
  
  Top 10 File Types:
  ----------------
$(
    $stats.FileTypes.GetEnumerator() | 
    Sort-Object Value -Descending | 
    Select-Object -First 10 | 
    ForEach-Object { "  $($_.Key): $($_.Value) files" }
)
  
  Top 10 Secret Types:
  -----------------
$(
    $stats.SecretTypes.GetEnumerator() | 
    Sort-Object Value -Descending | 
    Select-Object -First 10 | 
    ForEach-Object { "  $($_.Key): $($_.Value) findings" }
)
  
  Top 5 Directories with Secrets:
  ---------------------------
$(
    $stats.TopDirectories.GetEnumerator() | 
    Sort-Object Value -Descending | 
    Select-Object -First 5 | 
    ForEach-Object { "  $($_.Key): $($_.Value) secrets" }
)
  
  Performance Metrics:
  -----------------
  Average Processing Time per File: $([math]::Round($totalTime.TotalSeconds / $stats.ProcessedFiles, 2)) seconds
  Files Processed per Second: $([math]::Round($stats.ProcessedFiles / $totalTime.TotalSeconds, 2))
╚══════════════════════════════════════════════════════════════════════════════╝
"@

    return $statisticsReport
}

# модификация основного отчета
$summary = @"
$($asciiArt)

$(Generate-StatisticsReport)

╔══════════════════════════════════════════════════════════════════════════════╗
║                              Detailed Findings                                ║
╠══════════════════════════════════════════════════════════════════════════════╣

"@

# модификация формата отчета для включения критичности
$results | ForEach-Object {
    $summary += @"

Type: $($_.Type)
Criticality: $($_.Criticality)
File: $($_.File)
Line: $($_.Line)
Match: $($_.Match)
-------------------
"@
}

# сохранение результатов
$summary | Out-File $OutputFile

Write-Host "`nScan completed!" -ForegroundColor Green
Write-Host "Results saved to: $OutputFile" -ForegroundColor Yellow
Write-Host $summary 
