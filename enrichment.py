"""
정보 확장 모듈
WHOIS, DNS, SSL, 기술 스택 등 추가 정보를 수집합니다.
"""

import socket
import ssl
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import subprocess
import re
import json


class InfoEnrichment:
    """정보 확장 클래스 - 추가 정보를 수집합니다"""

    def __init__(self):
        self.timeout = 10

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """
        WHOIS 정보 조회

        Args:
            domain: 도메인명

        Returns:
            WHOIS 정보 딕셔너리
        """
        try:
            # whois 명령어 실행
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            whois_text = result.stdout

            # 주요 정보 파싱
            info = {
                'raw': whois_text,
                'registrar': self._extract_field(whois_text, r'Registrar:\s*(.+)'),
                'creation_date': self._extract_field(whois_text, r'Creation Date:\s*(.+)'),
                'expiration_date': self._extract_field(whois_text, r'Expir.*Date:\s*(.+)'),
                'name_servers': self._extract_nameservers(whois_text),
                'status': self._extract_field(whois_text, r'Status:\s*(.+)'),
                'registrant_org': self._extract_field(whois_text, r'Registrant Organization:\s*(.+)'),
                'registrant_country': self._extract_field(whois_text, r'Registrant Country:\s*(.+)')
            }

            return {'success': True, 'data': info}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'WHOIS 조회 시간 초과'}
        except FileNotFoundError:
            return {'success': False, 'error': 'whois 명령어가 설치되지 않음'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        DNS 레코드 조회 (A, AAAA, MX, TXT, CNAME)

        Args:
            domain: 도메인명

        Returns:
            DNS 레코드 딕셔너리
        """
        records = {}

        try:
            # A 레코드 (IPv4)
            try:
                a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
                records['A'] = list(set([addr[4][0] for addr in a_records]))
            except:
                records['A'] = []

            # AAAA 레코드 (IPv6)
            try:
                aaaa_records = socket.getaddrinfo(domain, None, socket.AF_INET6)
                records['AAAA'] = list(set([addr[4][0] for addr in aaaa_records]))
            except:
                records['AAAA'] = []

            # MX 레코드 (dig 사용)
            try:
                mx_result = subprocess.run(
                    ['dig', '+short', 'MX', domain],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                records['MX'] = [line.strip() for line in mx_result.stdout.split('\n') if line.strip()]
            except:
                records['MX'] = []

            # TXT 레코드 (dig 사용)
            try:
                txt_result = subprocess.run(
                    ['dig', '+short', 'TXT', domain],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                records['TXT'] = [line.strip() for line in txt_result.stdout.split('\n') if line.strip()]
            except:
                records['TXT'] = []

            return {'success': True, 'data': records}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_ssl_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        SSL/TLS 인증서 정보 조회

        Args:
            domain: 도메인명
            port: 포트 번호 (기본값: 443)

        Returns:
            SSL 인증서 정보 딕셔너리
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # 인증서 정보 추출
                    info = {
                        'subject': dict(x[0] for x in cert.get('subject', ())),
                        'issuer': dict(x[0] for x in cert.get('issuer', ())),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', []),
                        'protocol': ssock.version()
                    }

                    return {'success': True, 'data': info}

        except socket.timeout:
            return {'success': False, 'error': 'SSL 연결 시간 초과'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_http_headers(self, url: str) -> Dict[str, Any]:
        """
        HTTP 헤더 정보 조회

        Args:
            url: URL

        Returns:
            HTTP 헤더 딕셔너리
        """
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)

            headers = dict(response.headers)

            # 보안 헤더 체크
            security_headers = {
                'strict-transport-security': headers.get('Strict-Transport-Security'),
                'content-security-policy': headers.get('Content-Security-Policy'),
                'x-frame-options': headers.get('X-Frame-Options'),
                'x-content-type-options': headers.get('X-Content-Type-Options'),
                'x-xss-protection': headers.get('X-XSS-Protection'),
                'referrer-policy': headers.get('Referrer-Policy')
            }

            return {
                'success': True,
                'data': {
                    'status_code': response.status_code,
                    'headers': headers,
                    'security_headers': security_headers,
                    'server': headers.get('Server'),
                    'powered_by': headers.get('X-Powered-By')
                }
            }

        except requests.Timeout:
            return {'success': False, 'error': 'HTTP 요청 시간 초과'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def detect_technologies(self, url: str) -> Dict[str, Any]:
        """
        웹사이트 기술 스택 탐지

        Args:
            url: URL

        Returns:
            탐지된 기술 딕셔너리
        """
        technologies = {
            'frameworks': [],
            'cms': [],
            'analytics': [],
            'cdn': [],
            'server': [],
            'javascript': []
        }

        try:
            response = requests.get(url, timeout=self.timeout)
            html = response.text
            headers = dict(response.headers)

            # 서버 정보
            server = headers.get('Server', '')
            if server:
                technologies['server'].append(server)

            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies['server'].append(powered_by)

            # HTML 기반 탐지
            patterns = {
                'frameworks': {
                    'React': r'react',
                    'Vue.js': r'vue',
                    'Angular': r'ng-',
                    'Next.js': r'__next',
                    'Nuxt.js': r'__nuxt',
                    'Svelte': r'svelte'
                },
                'cms': {
                    'WordPress': r'wp-content|wp-includes',
                    'Drupal': r'drupal',
                    'Joomla': r'joomla',
                    'Ghost': r'ghost',
                    'Jekyll': r'jekyll'
                },
                'analytics': {
                    'Google Analytics': r'google-analytics\.com|ga\.js|gtag',
                    'Google Tag Manager': r'googletagmanager\.com',
                    'Mixpanel': r'mixpanel',
                    'Hotjar': r'hotjar'
                },
                'cdn': {
                    'Cloudflare': r'cloudflare',
                    'AWS CloudFront': r'cloudfront',
                    'Fastly': r'fastly',
                    'Akamai': r'akamai'
                }
            }

            for category, tech_patterns in patterns.items():
                for tech_name, pattern in tech_patterns.items():
                    if re.search(pattern, html, re.IGNORECASE):
                        technologies[category].append(tech_name)

            # JavaScript 라이브러리 탐지
            js_libs = {
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'Tailwind CSS': r'tailwindcss',
                'D3.js': r'd3\.js',
                'Chart.js': r'chart\.js'
            }

            for lib_name, pattern in js_libs.items():
                if re.search(pattern, html, re.IGNORECASE):
                    technologies['javascript'].append(lib_name)

            # 중복 제거
            for key in technologies:
                technologies[key] = list(set(technologies[key]))

            return {'success': True, 'data': technologies}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_social_media_links(self, html: str) -> List[str]:
        """
        HTML에서 소셜 미디어 링크 추출

        Args:
            html: HTML 문자열

        Returns:
            소셜 미디어 링크 리스트
        """
        patterns = [
            r'https?://(?:www\.)?twitter\.com/[\w\d_]+',
            r'https?://(?:www\.)?facebook\.com/[\w\d.]+',
            r'https?://(?:www\.)?instagram\.com/[\w\d_.]+',
            r'https?://(?:www\.)?linkedin\.com/(?:in|company)/[\w\d-]+',
            r'https?://(?:www\.)?github\.com/[\w\d-]+',
            r'https?://(?:www\.)?youtube\.com/(?:c|channel|user)/[\w\d-]+',
            r'https?://(?:www\.)?tiktok\.com/@[\w\d_.]+',
            r'https?://(?:www\.)?pinterest\.com/[\w\d_]+',
            r'https?://t\.me/[\w\d_]+'
        ]

        links = []
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            links.extend(matches)

        return list(set(links))

    def enrich_url(self, url: str) -> Dict[str, Any]:
        """
        URL에 대한 모든 확장 정보 수집

        Args:
            url: URL

        Returns:
            확장된 정보 딕셔너리
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        enriched_data = {
            'domain': domain,
            'whois': self.get_whois_info(domain),
            'dns': self.get_dns_records(domain),
            'ssl': self.get_ssl_info(domain),
            'headers': self.get_http_headers(url),
            'technologies': self.detect_technologies(url)
        }

        return enriched_data

    def _extract_field(self, text: str, pattern: str) -> Optional[str]:
        """정규표현식으로 필드 추출"""
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _extract_nameservers(self, text: str) -> List[str]:
        """네임서버 목록 추출"""
        pattern = r'Name Server:\s*(.+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return [ns.strip() for ns in matches]


# 편의 함수
def enrich_domain(domain: str) -> Dict[str, Any]:
    """
    도메인에 대한 확장 정보 수집 (간편 함수)

    Args:
        domain: 도메인명

    Returns:
        확장된 정보 딕셔너리
    """
    enricher = InfoEnrichment()
    return enricher.enrich_url(f"https://{domain}")


if __name__ == "__main__":
    # 테스트
    print("=" * 70)
    print("🔍 정보 확장 모듈 테스트")
    print("=" * 70)
    print()

    enricher = InfoEnrichment()

    # 테스트 도메인
    test_domain = "example.com"
    test_url = f"https://{test_domain}"

    print(f"📊 테스트 대상: {test_url}")
    print("-" * 70)
    print()

    # WHOIS 정보
    print("1. WHOIS 정보:")
    whois_info = enricher.get_whois_info(test_domain)
    if whois_info['success']:
        data = whois_info['data']
        print(f"  • 등록기관: {data.get('registrar', 'N/A')}")
        print(f"  • 생성일: {data.get('creation_date', 'N/A')}")
        print(f"  • 만료일: {data.get('expiration_date', 'N/A')}")
        print(f"  • 네임서버: {', '.join(data.get('name_servers', [])) or 'N/A'}")
    else:
        print(f"  ❌ {whois_info['error']}")
    print()

    # DNS 레코드
    print("2. DNS 레코드:")
    dns_info = enricher.get_dns_records(test_domain)
    if dns_info['success']:
        data = dns_info['data']
        print(f"  • A (IPv4): {', '.join(data.get('A', [])) or 'N/A'}")
        print(f"  • AAAA (IPv6): {', '.join(data.get('AAAA', [])) or 'N/A'}")
        print(f"  • MX: {', '.join(data.get('MX', [])) or 'N/A'}")
    else:
        print(f"  ❌ {dns_info['error']}")
    print()

    # SSL 인증서
    print("3. SSL 인증서:")
    ssl_info = enricher.get_ssl_info(test_domain)
    if ssl_info['success']:
        data = ssl_info['data']
        print(f"  • 발급자: {data['issuer'].get('organizationName', 'N/A')}")
        print(f"  • 유효기간: {data.get('not_before')} ~ {data.get('not_after')}")
        print(f"  • 프로토콜: {data.get('protocol')}")
    else:
        print(f"  ❌ {ssl_info['error']}")
    print()

    # HTTP 헤더
    print("4. HTTP 헤더:")
    headers_info = enricher.get_http_headers(test_url)
    if headers_info['success']:
        data = headers_info['data']
        print(f"  • 상태 코드: {data.get('status_code')}")
        print(f"  • 서버: {data.get('server', 'N/A')}")
        print(f"  • Powered-By: {data.get('powered_by', 'N/A')}")
        sec_headers = data.get('security_headers', {})
        sec_count = sum(1 for v in sec_headers.values() if v is not None)
        print(f"  • 보안 헤더: {sec_count}/6 설정됨")
    else:
        print(f"  ❌ {headers_info['error']}")
    print()

    # 기술 스택
    print("5. 기술 스택:")
    tech_info = enricher.detect_technologies(test_url)
    if tech_info['success']:
        data = tech_info['data']
        for category, techs in data.items():
            if techs:
                print(f"  • {category}: {', '.join(techs)}")
    else:
        print(f"  ❌ {tech_info['error']}")
    print()

    print("=" * 70)
    print("✅ 테스트 완료!")
    print("=" * 70)
