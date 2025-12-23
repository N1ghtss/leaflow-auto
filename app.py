#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Leaflow Auto Check-in Control Panel
Web-based management interface for the check-in system
Using local JSON config files for storage
"""

import os
import json
import hashlib
import secrets
import threading
import time
import re
import requests
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, make_response
from flask_cors import CORS
import jwt
import logging
from urllib.parse import urlparse, unquote
import random
import pytz
import hmac
import base64
import urllib.parse
import traceback

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

# Environment variables
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
PORT = int(os.getenv('PORT', '8181'))
CONFIG_DIR = os.getenv('CONFIG_DIR', './config')

# 设置时区为北京时间
TIMEZONE = pytz.timezone('Asia/Shanghai')

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ConfigManager:
    """配置文件管理类"""

    def __init__(self, config_dir=CONFIG_DIR):
        self.config_dir = config_dir
        self.accounts_file = os.path.join(config_dir, 'accounts.json')
        self.notification_file = os.path.join(config_dir, 'notification.json')
        self.lock = threading.Lock()
        self._init_config_files()

    def _init_config_files(self):
        """初始化配置文件"""
        os.makedirs(self.config_dir, exist_ok=True)

        # 初始化账号配置文件
        if not os.path.exists(self.accounts_file):
            self._save_json(self.accounts_file, {
                'next_id': 1,
                'accounts': []
            })
            logger.info(f"Created accounts config: {self.accounts_file}")

        # 初始化通知配置文件
        if not os.path.exists(self.notification_file):
            self._save_json(self.notification_file, self._default_notification_settings())
            logger.info(f"Created notification config: {self.notification_file}")

    def _default_notification_settings(self):
        """默认通知设置"""
        return {
            'enabled': False,
            'telegram': {
                'enabled': False,
                'bot_token': '',
                'user_id': '',
                'host': ''
            },
            'wechat': {
                'enabled': False,
                'webhook_key': '',
                'host': ''
            },
            'wxpusher': {
                'enabled': False,
                'app_token': '',
                'uid': '',
                'host': ''
            },
            'dingtalk': {
                'enabled': False,
                'access_token': '',
                'secret': '',
                'host': ''
            }
        }

    def _load_json(self, filepath):
        """加载 JSON 文件"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return None

    def _save_json(self, filepath, data):
        """保存 JSON 文件"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving {filepath}: {e}")
            return False

    def load_accounts_data(self):
        """加载账号数据（包含 next_id）"""
        with self.lock:
            data = self._load_json(self.accounts_file)
            if data is None:
                return {'next_id': 1, 'accounts': []}
            return data

    def save_accounts_data(self, data):
        """保存账号数据"""
        with self.lock:
            return self._save_json(self.accounts_file, data)

    def get_accounts(self, enabled_only=False):
        """获取账号列表"""
        data = self.load_accounts_data()
        accounts = data.get('accounts', [])
        if enabled_only:
            return [acc for acc in accounts if acc.get('enabled', True)]
        return accounts

    def get_account_by_id(self, account_id):
        """根据 ID 获取账号"""
        accounts = self.get_accounts()
        for acc in accounts:
            if acc.get('id') == account_id:
                return acc
        return None

    def add_account(self, account_data):
        """添加账号"""
        data = self.load_accounts_data()
        account_id = data['next_id']
        data['next_id'] += 1

        new_account = {
            'id': account_id,
            'name': account_data['name'],
            'token_data': account_data['token_data'],
            'enabled': True,
            'checkin_time_start': account_data.get('checkin_time_start', '06:30'),
            'checkin_time_end': account_data.get('checkin_time_end', '06:40'),
            'check_interval': account_data.get('check_interval', 60),
            'retry_count': account_data.get('retry_count', 2),
            'last_checkin_date': None,
            'created_at': datetime.now(TIMEZONE).isoformat()
        }

        data['accounts'].append(new_account)
        self.save_accounts_data(data)
        logger.info(f"Account '{account_data['name']}' added with ID {account_id}")
        return account_id

    def update_account(self, account_id, updates):
        """更新账号"""
        data = self.load_accounts_data()
        for acc in data['accounts']:
            if acc['id'] == account_id:
                for key, value in updates.items():
                    acc[key] = value
                acc['updated_at'] = datetime.now(TIMEZONE).isoformat()
                self.save_accounts_data(data)
                logger.info(f"Account {account_id} updated")
                return True
        return False

    def delete_account(self, account_id):
        """删除账号"""
        data = self.load_accounts_data()
        original_count = len(data['accounts'])
        data['accounts'] = [acc for acc in data['accounts'] if acc['id'] != account_id]
        if len(data['accounts']) < original_count:
            self.save_accounts_data(data)
            logger.info(f"Account {account_id} deleted")
            return True
        return False

    def load_notification_settings(self):
        """加载通知设置"""
        with self.lock:
            data = self._load_json(self.notification_file)
            if data is None:
                return self._default_notification_settings()
            return data

    def save_notification_settings(self, settings):
        """保存通知设置"""
        with self.lock:
            return self._save_json(self.notification_file, settings)


class CheckinHistoryManager:
    """签到历史管理类（内存存储）"""

    def __init__(self, max_records=200):
        self.history = []
        self.max_records = max_records
        self.lock = threading.Lock()
        self.total_checkins = 0
        self.successful_checkins = 0

    def add_record(self, account_id, account_name, success, message, retry_times=0):
        """添加签到记录"""
        with self.lock:
            record = {
                'account_id': account_id,
                'name': account_name,
                'success': success,
                'message': message,
                'retry_times': retry_times,
                'checkin_date': datetime.now(TIMEZONE).date().isoformat(),
                'created_at': datetime.now(TIMEZONE).isoformat()
            }
            self.history.insert(0, record)

            # 保持记录数量限制
            if len(self.history) > self.max_records:
                self.history = self.history[:self.max_records]

            # 更新统计
            self.total_checkins += 1
            if success:
                self.successful_checkins += 1

    def get_today_records(self):
        """获取今日签到记录"""
        today = datetime.now(TIMEZONE).date().isoformat()
        with self.lock:
            return [r for r in self.history if r['checkin_date'] == today]

    def get_all_records(self, limit=50):
        """获取所有签到记录"""
        with self.lock:
            return self.history[:limit]

    def clear_today(self):
        """清空今日记录"""
        today = datetime.now(TIMEZONE).date().isoformat()
        with self.lock:
            cleared_count = len([r for r in self.history if r['checkin_date'] == today])
            self.history = [r for r in self.history if r['checkin_date'] != today]
            return cleared_count

    def clear_all(self):
        """清空所有记录"""
        with self.lock:
            cleared_count = len(self.history)
            self.history = []
            self.total_checkins = 0
            self.successful_checkins = 0
            return cleared_count

    def get_stats(self):
        """获取统计信息"""
        with self.lock:
            return {
                'total_checkins': self.total_checkins,
                'successful_checkins': self.successful_checkins,
                'success_rate': round(self.successful_checkins / self.total_checkins * 100, 2) if self.total_checkins > 0 else 0
            }


# Initialize managers
config_manager = ConfigManager()
history_manager = CheckinHistoryManager()


# Notification class
class NotificationService:
    @staticmethod
    def send_notification(title, content, account_name=None):
        """Send notification through configured channels"""
        try:
            settings = config_manager.load_notification_settings()
            if not settings.get('enabled'):
                logger.info("Notifications disabled")
                return

            # Send Telegram notification
            telegram = settings.get('telegram', {})
            if telegram.get('enabled') and telegram.get('bot_token') and telegram.get('user_id'):
                NotificationService.send_telegram(
                    telegram['bot_token'],
                    telegram['user_id'],
                    title,
                    content,
                    telegram.get('host', '')
                )

            # Send WeChat Work notification
            wechat = settings.get('wechat', {})
            if wechat.get('enabled') and wechat.get('webhook_key'):
                NotificationService.send_wechat(
                    wechat['webhook_key'],
                    title,
                    content,
                    wechat.get('host', '')
                )

            # Send WxPusher notification
            wxpusher = settings.get('wxpusher', {})
            if wxpusher.get('enabled') and wxpusher.get('app_token') and wxpusher.get('uid'):
                NotificationService.send_wxpusher(
                    wxpusher['app_token'],
                    wxpusher['uid'],
                    title,
                    content,
                    wxpusher.get('host', '')
                )

            # Send DingTalk notification
            dingtalk = settings.get('dingtalk', {})
            if dingtalk.get('enabled') and dingtalk.get('access_token') and dingtalk.get('secret'):
                NotificationService.send_dingtalk(
                    dingtalk['access_token'],
                    dingtalk['secret'],
                    title,
                    content,
                    dingtalk.get('host', '')
                )

        except Exception as e:
            logger.error(f"Notification error: {e}")

    @staticmethod
    def send_telegram(token, chat_id, title, content, custom_host=''):
        """Send Telegram notification"""
        try:
            base_url = custom_host.rstrip('/') if custom_host else "https://api.telegram.org"
            url = f"{base_url}/bot{token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": f"📢 {title}\n\n{content}",
                "disable_web_page_preview": True
            }

            response = requests.post(url=url, data=data, timeout=30)
            result = response.json()

            if result.get("ok"):
                logger.info("Telegram notification sent successfully")
            else:
                logger.error(f"Telegram notification failed: {result.get('description')}")
        except Exception as e:
            logger.error(f"Telegram notification error: {e}")

    @staticmethod
    def send_wechat(webhook_key, title, content, custom_host=''):
        """Send WeChat Work notification"""
        try:
            base_url = custom_host.rstrip('/') if custom_host else "https://qyapi.weixin.qq.com"
            url = f"{base_url}/cgi-bin/webhook/send?key={webhook_key}"
            headers = {"Content-Type": "application/json;charset=utf-8"}
            data = {"msgtype": "text", "text": {"content": f"【{title}】\n\n{content}"}}

            response = requests.post(
                url=url,
                data=json.dumps(data),
                headers=headers,
                timeout=15
            ).json()

            if response.get("errcode") == 0:
                logger.info("WeChat Work notification sent successfully")
            else:
                logger.error(f"WeChat Work notification failed: {response.get('errmsg')}")
        except Exception as e:
            logger.error(f"WeChat Work notification error: {e}")

    @staticmethod
    def send_wxpusher(app_token, uid, title, content, custom_host=''):
        """Send WxPusher notification"""
        try:
            base_url = custom_host.rstrip('/') if custom_host else "https://wxpusher.zjiecode.com"
            url = f"{base_url}/api/send/message"

            html_content = f"""
            <div style="padding: 10px; color: #2c3e50; background: #ffffff;">
                <h2 style="color: inherit; margin: 0;">{title}</h2>
                <div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; color: #2c3e50;">
                    <pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; color: inherit;">{content}</pre>
                </div>
                <div style="margin-top: 10px; color: #7f8c8d; font-size: 12px;">
                    发送时间: {datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
            """

            data = {
                "appToken": app_token,
                "content": html_content,
                "summary": title[:20],
                "contentType": 2,
                "uids": [uid],
                "verifyPayType": 0
            }

            response = requests.post(url, json=data, timeout=30)
            result = response.json()

            if result.get("code") == 1000:
                logger.info("WxPusher notification sent successfully")
            else:
                logger.error(f"WxPusher notification failed: {result.get('msg')}")
        except Exception as e:
            logger.error(f"WxPusher notification error: {e}")

    @staticmethod
    def send_dingtalk(access_token, secret, title, content, custom_host=''):
        """Send DingTalk robot notification"""
        try:
            # 生成签名
            timestamp = str(round(time.time() * 1000))
            string_to_sign = f'{timestamp}\n{secret}'
            hmac_code = hmac.new(
                secret.encode('utf-8'),
                string_to_sign.encode('utf-8'),
                digestmod=hashlib.sha256
            ).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))

            # 构建URL
            base_url = custom_host.rstrip('/') if custom_host else "https://oapi.dingtalk.com"
            url = f'{base_url}/robot/send?access_token={access_token}&timestamp={timestamp}&sign={sign}'

            # 构建消息体
            data = {
                "msgtype": "text",
                "text": {
                    "content": f"【{title}】\n{content}"
                },
                "at": {
                    "isAtAll": False
                }
            }

            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, json=data, headers=headers, timeout=30)
            result = response.json()

            if result.get("errcode") == 0:
                logger.info("DingTalk notification sent successfully")
            else:
                logger.error(f"DingTalk notification failed: {result.get('errmsg')}")
        except Exception as e:
            logger.error(f"DingTalk notification error: {e}")


# Leaflow check-in class
class LeafLowCheckin:
    def __init__(self):
        self.checkin_url = "https://checkin.leaflow.net"
        self.main_site = "https://leaflow.net"
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

    def create_session(self, token_data):
        """Create session with authentication"""
        session = requests.Session()

        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        if 'cookies' in token_data:
            for name, value in token_data['cookies'].items():
                session.cookies.set(name, value)

        if 'headers' in token_data:
            session.headers.update(token_data['headers'])

        return session

    def test_authentication(self, session, account_name):
        """Test if authentication is valid"""
        try:
            test_urls = [
                f"{self.main_site}/dashboard",
                f"{self.main_site}/profile",
                f"{self.main_site}/user",
                self.checkin_url,
            ]

            for url in test_urls:
                response = session.get(url, timeout=30)

                if response.status_code == 200:
                    content = response.text.lower()
                    if any(indicator in content for indicator in ['dashboard', 'profile', 'user', 'logout', 'welcome']):
                        logger.info(f"✅ [{account_name}] Authentication valid")
                        return True, "Authentication successful"
                elif response.status_code in [301, 302, 303]:
                    location = response.headers.get('location', '')
                    if 'login' not in location.lower():
                        logger.info(f"✅ [{account_name}] Authentication valid (redirect)")
                        return True, "Authentication successful (redirect)"

            return False, "Authentication failed - no valid authenticated pages found"

        except Exception as e:
            return False, f"Authentication test error: {str(e)}"

    def perform_checkin(self, session, account_name):
        """Perform check-in"""
        logger.info(f"🎯 [{account_name}] Performing checkin...")

        try:
            # Try direct check-in page
            response = session.get(self.checkin_url, timeout=30)

            if response.status_code == 200:
                result = self.analyze_and_checkin(session, response.text, self.checkin_url, account_name)
                if result[0]:
                    return result

            # Try API endpoints
            api_endpoints = [
                f"{self.checkin_url}/api/checkin",
                f"{self.checkin_url}/checkin",
                f"{self.main_site}/api/checkin",
                f"{self.main_site}/checkin"
            ]

            for endpoint in api_endpoints:
                try:
                    # GET request
                    response = session.get(endpoint, timeout=30)
                    if response.status_code == 200:
                        success, message = self.check_checkin_response(response.text)
                        if success:
                            return True, message

                    # POST request
                    response = session.post(endpoint, data={'checkin': '1'}, timeout=30)
                    if response.status_code == 200:
                        success, message = self.check_checkin_response(response.text)
                        if success:
                            return True, message

                except Exception as e:
                    logger.debug(f"[{account_name}] API endpoint {endpoint} failed: {str(e)}")
                    continue

            return False, "All checkin methods failed"

        except Exception as e:
            return False, f"Checkin error: {str(e)}"

    def analyze_and_checkin(self, session, html_content, page_url, account_name):
        """Analyze page and perform check-in"""
        if self.already_checked_in(html_content):
            return True, "Already checked in today"

        if not self.is_checkin_page(html_content):
            return False, "Not a checkin page"

        try:
            checkin_data = {'checkin': '1', 'action': 'checkin', 'daily': '1'}

            csrf_token = self.extract_csrf_token(html_content)
            if csrf_token:
                checkin_data['_token'] = csrf_token
                checkin_data['csrf_token'] = csrf_token

            response = session.post(page_url, data=checkin_data, timeout=30)

            if response.status_code == 200:
                return self.check_checkin_response(response.text)

        except Exception as e:
            logger.debug(f"[{account_name}] POST checkin failed: {str(e)}")

        return False, "Failed to perform checkin"

    def already_checked_in(self, html_content):
        """Check if already checked in"""
        content_lower = html_content.lower()
        indicators = [
            'already checked in', '今日已签到', 'checked in today',
            'attendance recorded', '已完成签到', 'completed today'
        ]
        return any(indicator in content_lower for indicator in indicators)

    def is_checkin_page(self, html_content):
        """Check if it's a check-in page"""
        content_lower = html_content.lower()
        indicators = ['check-in', 'checkin', '签到', 'attendance', 'daily']
        return any(indicator in content_lower for indicator in indicators)

    def extract_csrf_token(self, html_content):
        """Extract CSRF token"""
        patterns = [
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def check_checkin_response(self, html_content):
        """Check check-in response"""
        content_lower = html_content.lower()

        success_indicators = [
            'check-in successful', 'checkin successful', '签到成功',
            'attendance recorded', 'earned reward', '获得奖励',
            'success', '成功', 'completed'
        ]

        if any(indicator in content_lower for indicator in success_indicators):
            reward_patterns = [
                r'获得奖励[^\d]*(\d+\.?\d*)\s*元',
                r'earned.*?(\d+\.?\d*)\s*(credits?|points?)',
                r'(\d+\.?\d*)\s*(credits?|points?|元)'
            ]

            for pattern in reward_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    reward = match.group(1)
                    return True, f"Check-in successful! Earned {reward} credits"

            return True, "Check-in successful!"

        return False, "Checkin response indicates failure"


# Helper function to parse cookie string
def parse_cookie_string(cookie_input):
    """Parse cookie string in various formats"""
    cookie_input = cookie_input.strip()

    # Try to parse as JSON first
    if cookie_input.startswith('{'):
        try:
            data = json.loads(cookie_input)
            if 'cookies' in data:
                return data
            else:
                return {'cookies': data}
        except json.JSONDecodeError:
            pass

    # Parse as semicolon-separated cookie string
    cookies = {}
    cookie_pairs = re.split(r';\s*', cookie_input)

    for pair in cookie_pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            key = key.strip()
            value = value.strip()
            if key:
                cookies[key] = value

    if cookies:
        return {'cookies': cookies}

    raise ValueError("Invalid cookie format")


# JWT authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'message': 'Token validation failed!'}), 401

    return decorated


# Scheduler class
class CheckinScheduler:
    def __init__(self):
        self.scheduler_thread = None
        self.running = False
        self.leaflow_checkin = LeafLowCheckin()
        self.checkin_tasks = {}

    def start(self):
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduler_thread.start()
            logger.info("Scheduler started")

    def stop(self):
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Scheduler stopped")

    def _run_scheduler(self):
        """调度器主循环"""
        while self.running:
            try:
                # 获取当前北京时间
                now = datetime.now(TIMEZONE)
                current_date = now.date()

                # 从配置文件获取启用的账户
                accounts = config_manager.get_accounts(enabled_only=True)

                for account in accounts:
                    try:
                        account_id = account['id']

                        # 检查今天是否已经签到
                        last_checkin_date = account.get('last_checkin_date')
                        if last_checkin_date:
                            if isinstance(last_checkin_date, str):
                                last_checkin_date = datetime.strptime(last_checkin_date, '%Y-%m-%d').date()
                            if last_checkin_date == current_date:
                                continue

                        # 获取签到时间范围
                        start_time_str = account.get('checkin_time_start', '06:30')
                        end_time_str = account.get('checkin_time_end', '06:40')
                        check_interval = account.get('check_interval', 60)

                        # 解析时间
                        start_hour, start_minute = map(int, start_time_str.split(':'))
                        end_hour, end_minute = map(int, end_time_str.split(':'))

                        # 创建今天的开始和结束时间
                        start_time = now.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
                        end_time = now.replace(hour=end_hour, minute=end_minute, second=59, microsecond=999999)

                        # 检查是否在签到时间范围内
                        if start_time <= now <= end_time:
                            task_key = f"{account_id}_{current_date}"

                            if task_key not in self.checkin_tasks:
                                self.checkin_tasks[task_key] = {
                                    'last_check': None,
                                    'completed': False,
                                    'retry_count': 0
                                }

                            task = self.checkin_tasks[task_key]

                            if not task['completed']:
                                if task['last_check'] is None or \
                                   (now - task['last_check']).total_seconds() >= check_interval:
                                    task['last_check'] = now
                                    threading.Thread(
                                        target=self.perform_checkin_with_delay,
                                        args=(account_id, task_key),
                                        daemon=True
                                    ).start()
                    except Exception as e:
                        logger.error(f"Error processing account {account.get('id', 'unknown')}: {e}")
                        continue

                # 清理过期的任务记录
                expired_keys = []
                for key in self.checkin_tasks:
                    if not key.endswith(str(current_date)):
                        expired_keys.append(key)
                for key in expired_keys:
                    del self.checkin_tasks[key]

            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                logger.error(traceback.format_exc())

            time.sleep(30)

    def perform_checkin_with_delay(self, account_id, task_key):
        """带随机延迟的签到执行"""
        try:
            delay = random.randint(0, 30)
            time.sleep(delay)

            success = self.perform_checkin(account_id)

            if task_key in self.checkin_tasks:
                self.checkin_tasks[task_key]['completed'] = success

        except Exception as e:
            logger.error(f"Checkin with delay error: {e}")
            logger.error(traceback.format_exc())

    def perform_checkin(self, account_id, retry_attempt=0):
        """Perform check-in for an account with retry mechanism"""
        try:
            account = config_manager.get_account_by_id(account_id)
            if not account or not account.get('enabled'):
                return False

            current_date = datetime.now(TIMEZONE).date()

            # 检查今天是否已经签到（通过历史记录）
            today_records = history_manager.get_today_records()
            already_checked = any(r['account_id'] == account_id and r['success'] for r in today_records)
            if already_checked:
                logger.info(f"Account {account['name']} already checked in today")
                return True

            # Parse token data
            token_data = account['token_data']
            if isinstance(token_data, str):
                token_data = json.loads(token_data)

            # Create session and perform check-in
            session = self.leaflow_checkin.create_session(token_data)

            # Test authentication
            auth_result = self.leaflow_checkin.test_authentication(session, account['name'])
            if not auth_result[0]:
                success = False
                message = f"Authentication failed: {auth_result[1]}"
            else:
                # Perform check-in
                success, message = self.leaflow_checkin.perform_checkin(session, account['name'])

            # 如果失败且还有重试次数
            retry_count = account.get('retry_count', 2)
            if not success and retry_attempt < retry_count:
                logger.info(f"Retrying checkin for {account['name']} (attempt {retry_attempt + 1}/{retry_count})")
                time.sleep(5)
                return self.perform_checkin(account_id, retry_attempt + 1)

            # Record check-in result
            history_manager.add_record(
                account_id=account_id,
                account_name=account['name'],
                success=success,
                message=message,
                retry_times=retry_attempt
            )

            # 更新最后签到日期
            if success:
                config_manager.update_account(account_id, {
                    'last_checkin_date': current_date.isoformat()
                })

            logger.info(f"Check-in for {account['name']}: {'Success' if success else 'Failed'} - {message}")

            # Send notification
            notification_title = f"Leaflow签到结果 - {account['name']}"
            status_emoji = '✅' if success else '❌'
            notification_content = f"状态: {status_emoji} {'成功' if success else '失败'}\n消息: {message}\n重试次数: {retry_attempt}"
            NotificationService.send_notification(notification_title, notification_content, account['name'])

            return success

        except Exception as e:
            logger.error(f"Check-in error for account {account_id}: {e}")
            logger.error(traceback.format_exc())

            # Send error notification
            try:
                account = config_manager.get_account_by_id(account_id)
                if account:
                    NotificationService.send_notification(
                        f"Leaflow签到错误 - {account['name']}",
                        f"错误: {str(e)}",
                        account['name']
                    )
            except:
                pass

            return False


scheduler = CheckinScheduler()


# Routes
@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """Handle login requests"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        username = data.get('username')
        password = data.get('password')

        logger.info(f"Login attempt for user: {username}")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            token = jwt.encode({
                'user': username,
                'exp': datetime.utcnow() + timedelta(days=7)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            logger.info(f"Login successful for user: {username}")
            return jsonify({'token': token, 'message': 'Login successful'})

        logger.warning(f"Login failed for user: {username}")
        return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': 'Login error'}), 500


@app.route('/api/verify', methods=['GET'])
@token_required
def verify_token():
    """Verify if token is valid"""
    return jsonify({'valid': True})


@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard():
    """Get dashboard statistics"""
    try:
        accounts = config_manager.get_accounts()
        enabled_accounts = [a for a in accounts if a.get('enabled', True)]

        today_checkins = history_manager.get_today_records()
        stats = history_manager.get_stats()

        return jsonify({
            'total_accounts': len(accounts),
            'enabled_accounts': len(enabled_accounts),
            'today_checkins': today_checkins[:20],
            'total_checkins': stats['total_checkins'],
            'successful_checkins': stats['successful_checkins'],
            'success_rate': stats['success_rate']
        })

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500


@app.route('/api/accounts', methods=['GET'])
@token_required
def get_accounts():
    """Get all accounts"""
    try:
        accounts = config_manager.get_accounts()
        # 不返回 token_data，保护敏感信息
        safe_accounts = []
        for acc in accounts:
            safe_acc = {k: v for k, v in acc.items() if k != 'token_data'}
            safe_accounts.append(safe_acc)
        return jsonify(safe_accounts)
    except Exception as e:
        logger.error(f"Get accounts error: {e}")
        return jsonify({'error': 'Failed to load accounts'}), 500


@app.route('/api/accounts', methods=['POST'])
@token_required
def add_account():
    """Add a new account"""
    try:
        data = request.get_json()
        name = data.get('name')
        cookie_input = data.get('token_data', data.get('cookie_data', ''))
        checkin_time_start = data.get('checkin_time_start', '06:30')
        checkin_time_end = data.get('checkin_time_end', '06:40')
        check_interval = data.get('check_interval', 60)
        retry_count = data.get('retry_count', 2)

        if not name or not cookie_input:
            return jsonify({'message': 'Name and cookie data are required'}), 400

        # Check if name already exists
        existing = config_manager.get_accounts()
        if any(acc['name'] == name for acc in existing):
            return jsonify({'message': 'Account name already exists'}), 400

        # Parse cookie input
        if isinstance(cookie_input, str):
            token_data = parse_cookie_string(cookie_input)
        else:
            token_data = cookie_input

        account_id = config_manager.add_account({
            'name': name,
            'token_data': token_data,
            'checkin_time_start': checkin_time_start,
            'checkin_time_end': checkin_time_end,
            'check_interval': check_interval,
            'retry_count': retry_count
        })

        return jsonify({'message': 'Account added successfully', 'id': account_id})

    except ValueError as e:
        return jsonify({'message': f'Invalid cookie format: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Add account error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/accounts/<int:account_id>', methods=['PUT'])
@token_required
def update_account(account_id):
    """Update an account"""
    try:
        data = request.get_json()

        updates = {}

        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])

        if 'checkin_time_start' in data:
            updates['checkin_time_start'] = data['checkin_time_start']

        if 'checkin_time_end' in data:
            updates['checkin_time_end'] = data['checkin_time_end']

        if 'check_interval' in data:
            updates['check_interval'] = int(data['check_interval'])

        if 'retry_count' in data:
            updates['retry_count'] = int(data['retry_count'])

        if 'token_data' in data or 'cookie_data' in data:
            cookie_input = data.get('token_data', data.get('cookie_data', ''))
            if isinstance(cookie_input, str):
                token_data = parse_cookie_string(cookie_input)
            else:
                token_data = cookie_input
            updates['token_data'] = token_data

        if updates:
            success = config_manager.update_account(account_id, updates)
            if success:
                return jsonify({'message': 'Account updated successfully'})
            else:
                return jsonify({'message': 'Account not found'}), 404

        return jsonify({'message': 'No updates provided'}), 400

    except Exception as e:
        logger.error(f"Update account error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@token_required
def delete_account(account_id):
    """Delete an account"""
    try:
        success = config_manager.delete_account(account_id)
        if success:
            return jsonify({'message': 'Account deleted successfully'})
        else:
            return jsonify({'message': 'Account not found'}), 404
    except Exception as e:
        logger.error(f"Delete account error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/checkin/clear', methods=['POST'])
@token_required
def clear_checkin_history():
    """Clear checkin history"""
    try:
        data = request.get_json()
        clear_type = data.get('type', 'today')

        if clear_type == 'today':
            cleared = history_manager.clear_today()
            # 重置今日的最后签到日期
            today = datetime.now(TIMEZONE).date().isoformat()
            accounts = config_manager.get_accounts()
            for acc in accounts:
                if acc.get('last_checkin_date') == today:
                    config_manager.update_account(acc['id'], {'last_checkin_date': None})
            message = f"Today's checkin history cleared ({cleared} records)"
        elif clear_type == 'all':
            cleared = history_manager.clear_all()
            # 重置所有最后签到日期
            accounts = config_manager.get_accounts()
            for acc in accounts:
                config_manager.update_account(acc['id'], {'last_checkin_date': None})
            message = f"All checkin history cleared ({cleared} records)"
        else:
            return jsonify({'message': 'Invalid clear type'}), 400

        logger.info(f"Checkin history cleared ({clear_type})")
        return jsonify({'message': message})
    except Exception as e:
        logger.error(f"Clear checkin history error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/notification', methods=['GET'])
@token_required
def get_notification_settings():
    """Get notification settings"""
    try:
        settings = config_manager.load_notification_settings()

        # 转换为前端期望的格式
        response = {
            'enabled': settings.get('enabled', False),
            'telegram_enabled': settings.get('telegram', {}).get('enabled', False),
            'telegram_bot_token': settings.get('telegram', {}).get('bot_token', ''),
            'telegram_user_id': settings.get('telegram', {}).get('user_id', ''),
            'telegram_host': settings.get('telegram', {}).get('host', ''),
            'wechat_enabled': settings.get('wechat', {}).get('enabled', False),
            'wechat_webhook_key': settings.get('wechat', {}).get('webhook_key', ''),
            'wechat_host': settings.get('wechat', {}).get('host', ''),
            'wxpusher_enabled': settings.get('wxpusher', {}).get('enabled', False),
            'wxpusher_app_token': settings.get('wxpusher', {}).get('app_token', ''),
            'wxpusher_uid': settings.get('wxpusher', {}).get('uid', ''),
            'wxpusher_host': settings.get('wxpusher', {}).get('host', ''),
            'dingtalk_enabled': settings.get('dingtalk', {}).get('enabled', False),
            'dingtalk_access_token': settings.get('dingtalk', {}).get('access_token', ''),
            'dingtalk_secret': settings.get('dingtalk', {}).get('secret', ''),
            'dingtalk_host': settings.get('dingtalk', {}).get('host', '')
        }

        return jsonify(response)
    except Exception as e:
        logger.error(f"Get notification settings error: {e}")
        return jsonify({'error': 'Failed to load settings'}), 500


@app.route('/api/notification', methods=['PUT'])
@token_required
def update_notification_settings():
    """Update notification settings"""
    try:
        data = request.get_json()
        logger.info(f"Updating notification settings")

        # 转换为内部存储格式
        settings = {
            'enabled': data.get('enabled', False),
            'telegram': {
                'enabled': data.get('telegram_enabled', False),
                'bot_token': data.get('telegram_bot_token', ''),
                'user_id': data.get('telegram_user_id', ''),
                'host': data.get('telegram_host', '')
            },
            'wechat': {
                'enabled': data.get('wechat_enabled', False),
                'webhook_key': data.get('wechat_webhook_key', ''),
                'host': data.get('wechat_host', '')
            },
            'wxpusher': {
                'enabled': data.get('wxpusher_enabled', False),
                'app_token': data.get('wxpusher_app_token', ''),
                'uid': data.get('wxpusher_uid', ''),
                'host': data.get('wxpusher_host', '')
            },
            'dingtalk': {
                'enabled': data.get('dingtalk_enabled', False),
                'access_token': data.get('dingtalk_access_token', ''),
                'secret': data.get('dingtalk_secret', ''),
                'host': data.get('dingtalk_host', '')
            }
        }

        config_manager.save_notification_settings(settings)
        logger.info("Notification settings updated successfully")

        return jsonify({'message': 'Notification settings updated successfully'})
    except Exception as e:
        logger.error(f"Update notification settings error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/checkin/manual/<int:account_id>', methods=['POST'])
@token_required
def manual_checkin(account_id):
    """Trigger manual check-in"""
    try:
        threading.Thread(target=scheduler.perform_checkin, args=(account_id,), daemon=True).start()
        return jsonify({'message': 'Manual check-in triggered'})
    except Exception as e:
        logger.error(f"Manual checkin error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


@app.route('/api/test/notification', methods=['POST'])
@token_required
def test_notification():
    """Test notification settings"""
    try:
        NotificationService.send_notification(
            "测试通知",
            "这是来自Leaflow自动签到系统的测试通知。如果您收到此消息，说明您的通知设置正常工作！",
            "系统测试"
        )
        return jsonify({'message': 'Test notification sent'})
    except Exception as e:
        logger.error(f"Test notification error: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 400


# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Leaflow Auto Check-in Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .login-box { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        .login-box h2 { margin-bottom: 30px; color: #333; text-align: center; font-size: 24px; }

        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; transition: all 0.3s; }
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus { border-color: #667eea; outline: none; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .form-group-inline { display: flex; align-items: center; gap: 10px; }
        .form-group-inline input[type="checkbox"] { width: auto; margin: 0; }

        .notification-channel { background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .notification-channel h4 { color: #2d3748; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .channel-toggle { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }

        .btn { padding: 12px 24px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.3s; display: inline-block; text-align: center; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-full { width: 100%; }
        .btn-sm { padding: 8px 16px; font-size: 13px; }
        .btn-danger { background: linear-gradient(135deg, #f56565, #e53e3e); }
        .btn-danger:hover { box-shadow: 0 5px 15px rgba(245, 101, 101, 0.4); }
        .btn-success { background: linear-gradient(135deg, #48bb78, #38a169); }
        .btn-success:hover { box-shadow: 0 5px 15px rgba(72, 187, 120, 0.4); }
        .btn-info { background: linear-gradient(135deg, #4299e1, #3182ce); }
        .btn-info:hover { box-shadow: 0 5px 15px rgba(66, 153, 225, 0.4); }
        .btn-warning { background: linear-gradient(135deg, #ed8936, #dd6b20); }
        .btn-warning:hover { box-shadow: 0 5px 15px rgba(237, 137, 54, 0.4); }

        .dashboard { display: none; padding: 20px; background: #f7fafc; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px 30px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
        .header-content { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        .header h1 { color: #2d3748; font-size: 24px; display: flex; align-items: center; gap: 10px; }
        .header-actions { display: flex; gap: 10px; align-items: center; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); transition: all 0.3s; }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 5px 20px rgba(0,0,0,0.12); }
        .stat-card h3 { color: #718096; font-size: 14px; margin-bottom: 12px; font-weight: 500; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #2d3748; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

        .section { background: white; padding: 30px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .section h2 { color: #2d3748; font-size: 20px; display: flex; align-items: center; gap: 10px; }
        .button-group { display: flex; gap: 10px; flex-wrap: wrap; }

        .table-wrapper { overflow-x: auto; margin: -10px; padding: 10px; }
        .table { width: 100%; border-collapse: separate; border-spacing: 0; }
        .table th, .table td { padding: 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f7fafc; font-weight: 600; color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
        .table tbody tr { transition: background 0.2s; }
        .table tbody tr:hover { background: #f7fafc; }

        .badge { padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; display: inline-block; }
        .badge-success { background: #c6f6d5; color: #22543d; }
        .badge-danger { background: #fed7d7; color: #742a2a; }
        .badge-info { background: #bee3f8; color: #2c5282; }

        .switch { position: relative; display: inline-block; width: 50px; height: 26px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #cbd5e0; transition: .4s; border-radius: 26px; }
        .slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background: linear-gradient(135deg, #667eea, #764ba2); }
        input:checked + .slider:before { transform: translateX(24px); }

        .time-range-input { display: flex; align-items: center; gap: 8px; }
        .time-range-input input[type="time"] { border: 2px solid #e0e0e0; padding: 6px; border-radius: 6px; font-size: 13px; }
        .interval-input { display: flex; align-items: center; gap: 8px; }
        .interval-input input[type="number"] { width: 80px; border: 2px solid #e0e0e0; padding: 6px; border-radius: 6px; font-size: 13px; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); justify-content: center; align-items: center; padding: 20px; z-index: 1000; }
        .modal-content { background: white; padding: 30px; border-radius: 15px; width: 100%; max-width: 600px; max-height: 90vh; overflow-y: auto; animation: modalSlideIn 0.3s ease; }
        @keyframes modalSlideIn { from { transform: translateY(-50px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .modal-header { margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
        .modal-header h3 { color: #2d3748; font-size: 20px; }
        .close { font-size: 28px; cursor: pointer; color: #a0aec0; background: none; border: none; padding: 0; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; border-radius: 50%; transition: all 0.3s; }
        .close:hover { background: #f7fafc; color: #4a5568; }

        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

        .toast { position: fixed; bottom: 20px; right: 20px; background: white; padding: 16px 24px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); display: none; animation: slideInUp 0.3s ease; z-index: 2000; max-width: 350px; }
        @keyframes slideInUp { from { transform: translateY(100px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .toast.success { border-left: 4px solid #48bb78; }
        .toast.error { border-left: 4px solid #f56565; }
        .toast.info { border-left: 4px solid #4299e1; }

        .error-message { color: #e53e3e; font-size: 14px; margin-top: 10px; display: none; }
        .format-hint { font-size: 12px; color: #718096; margin-top: 5px; }
        .help-link { color: #667eea; text-decoration: none; font-size: 12px; }
        .help-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div id="toast" class="toast"></div>

    <div class="login-container" id="loginContainer">
        <div class="login-box">
            <h2>🔐 管理员登录</h2>
            <div id="loginForm">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" id="username" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" id="password" required autocomplete="current-password">
                </div>
                <button type="button" class="btn btn-full" id="loginBtn" onclick="handleLogin()">登录</button>
                <div class="error-message" id="loginError"></div>
            </div>
        </div>
    </div>

    <div class="dashboard" id="dashboard">
        <div class="container">
            <div class="header">
                <div class="header-content">
                    <h1>📊 Leaflow 自动签到控制面板</h1>
                    <div class="header-actions">
                        <button class="btn btn-danger btn-sm" onclick="logout()">退出</button>
                    </div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card"><h3>账号总数</h3><div class="value" id="totalAccounts">0</div></div>
                <div class="stat-card"><h3>活跃账号</h3><div class="value" id="activeAccounts">0</div></div>
                <div class="stat-card"><h3>签到总数</h3><div class="value" id="totalCheckins">0</div></div>
                <div class="stat-card"><h3>成功率</h3><div class="value" id="successRate">0%</div></div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>📅 今日签到记录</h2>
                    <div class="button-group">
                        <button class="btn btn-warning btn-sm" onclick="clearCheckinHistory('today')">清空今日记录</button>
                        <button class="btn btn-danger btn-sm" onclick="clearCheckinHistory('all')">清空所有记录</button>
                    </div>
                </div>
                <div class="table-wrapper">
                    <table class="table">
                        <thead><tr><th>账号</th><th>状态</th><th>消息</th><th>重试次数</th><th>时间</th></tr></thead>
                        <tbody id="todayCheckins"><tr><td colspan="5" style="text-align: center; color: #a0aec0;"><div class="spinner"></div></td></tr></tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>👥 账号管理</h2>
                    <button class="btn btn-success btn-sm" onclick="showAddAccountModal()">+ 添加账号</button>
                </div>
                <div class="table-wrapper">
                    <table class="table">
                        <thead><tr><th>名称</th><th>状态</th><th>签到时间段</th><th>检查间隔</th><th>重试次数</th><th>操作</th></tr></thead>
                        <tbody id="accountsList"><tr><td colspan="6" style="text-align: center; color: #a0aec0;"><div class="spinner"></div></td></tr></tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>🔔 通知设置</h2>
                    <button class="btn btn-info btn-sm" onclick="testNotification()">测试通知</button>
                </div>
                <div class="form-group"><div class="form-group-inline"><input type="checkbox" id="notifyEnabled"><label for="notifyEnabled" style="margin-bottom: 0;">启用通知功能</label></div></div>

                <div class="notification-channel">
                    <h4>📱 Telegram 通知设置</h4>
                    <div class="channel-toggle"><input type="checkbox" id="telegramEnabled"><label for="telegramEnabled">启用 Telegram 通知</label></div>
                    <div class="form-group"><label>Bot Token</label><input type="text" id="tgBotToken" placeholder="从 @BotFather 获取的 Bot Token"></div>
                    <div class="form-group"><label>User ID</label><input type="text" id="tgUserId" placeholder="接收通知的用户ID"></div>
                    <div class="form-group"><label>API地址（可选）</label><input type="text" id="telegramHost" placeholder="https://api.telegram.org"><div class="format-hint">留空使用默认地址</div></div>
                </div>

                <div class="notification-channel">
                    <h4>💼 企业微信通知设置</h4>
                    <div class="channel-toggle"><input type="checkbox" id="wechatEnabled"><label for="wechatEnabled">启用企业微信通知</label></div>
                    <div class="form-group"><label>Webhook Key</label><input type="text" id="wechatKey" placeholder="企业微信机器人的 Webhook Key"></div>
                    <div class="form-group"><label>API地址（可选）</label><input type="text" id="wechatHost" placeholder="https://qyapi.weixin.qq.com"><div class="format-hint">留空使用默认地址</div></div>
                </div>

                <div class="notification-channel">
                    <h4>📨 WxPusher 消息通知设置</h4>
                    <div class="channel-toggle"><input type="checkbox" id="wxpusherEnabled"><label for="wxpusherEnabled">启用 WxPusher 通知</label></div>
                    <div class="form-group"><label>APP Token</label><input type="text" id="wxpusherAppToken" placeholder="AT_xxx"><div class="format-hint"><a href="https://wxpusher.zjiecode.com/docs/#/" target="_blank" class="help-link">访问 WxPusher 文档获取 Token 和 UID</a></div></div>
                    <div class="form-group"><label>UID</label><input type="text" id="wxpusherUid" placeholder="UID_xxx"></div>
                    <div class="form-group"><label>API地址（可选）</label><input type="text" id="wxpusherHost" placeholder="https://wxpusher.zjiecode.com"><div class="format-hint">留空使用默认地址</div></div>
                </div>

                <div class="notification-channel">
                    <h4>🤖 钉钉机器人通知设置</h4>
                    <div class="channel-toggle"><input type="checkbox" id="dingtalkEnabled"><label for="dingtalkEnabled">启用钉钉机器人通知</label></div>
                    <div class="form-group"><label>Access Token</label><input type="text" id="dingtalkAccessToken" placeholder="机器人的 Access Token"><div class="format-hint"><a href="https://open.dingtalk.com/document/orgapp/obtain-the-webhook-address-of-a-custom-robot" target="_blank" class="help-link">获取钉钉机器人配置</a></div></div>
                    <div class="form-group"><label>加签密钥</label><input type="text" id="dingtalkSecret" placeholder="安全设置中的加签密钥"></div>
                    <div class="form-group"><label>API地址（可选）</label><input type="text" id="dingtalkHost" placeholder="https://oapi.dingtalk.com"><div class="format-hint">留空使用默认地址</div></div>
                </div>

                <button class="btn" onclick="saveNotificationSettings()">保存通知设置</button>
            </div>
        </div>
    </div>

    <div class="modal" id="addAccountModal">
        <div class="modal-content">
            <div class="modal-header"><h3>添加新账号</h3><button class="close" onclick="closeModal('addAccountModal')">&times;</button></div>
            <div id="addAccountForm">
                <div class="form-group"><label>账号名称</label><input type="text" id="accountName" required></div>
                <div class="form-group"><label>签到时间段（北京时间）</label><div class="time-range-input"><input type="time" id="checkinTimeStart" value="06:30" required><span>至</span><input type="time" id="checkinTimeEnd" value="06:40" required></div><div class="format-hint">将在此时间段内随机执行签到</div></div>
                <div class="form-group"><label>检查间隔（秒）</label><input type="number" id="checkInterval" value="60" min="30" max="3600" required><div class="format-hint">在时间段内每隔多少秒检查一次是否需要签到</div></div>
                <div class="form-group"><label>重试次数</label><input type="number" id="retryCount" value="2" min="0" max="5" required><div class="format-hint">签到失败时的重试次数（0表示不重试）</div></div>
                <div class="form-group"><label>Cookie 数据</label><textarea id="tokenData" rows="6" placeholder='支持格式：
1. JSON格式: {"cookies": {"key": "value"}}
2. 分号分隔: key1=value1; key2=value2
3. 完整cookie: leaflow_session=xxx; remember_xxx=xxx; XSRF-TOKEN=xxx' required></textarea><div class="format-hint">从浏览器开发者工具(F12) → Network → 请求头 → Cookie 复制</div></div>
                <div style="display: flex; gap: 10px; margin-top: 20px;"><button type="button" class="btn btn-full" onclick="addAccount()">添加账号</button><button type="button" class="btn btn-danger" onclick="closeModal('addAccountModal')">取消</button></div>
            </div>
        </div>
    </div>

    <div class="modal" id="editAccountModal">
        <div class="modal-content">
            <div class="modal-header"><h3>修改账号</h3><button class="close" onclick="closeModal('editAccountModal')">&times;</button></div>
            <div id="editAccountForm">
                <input type="hidden" id="editAccountId">
                <div class="form-group"><label>Cookie 数据</label><textarea id="editTokenData" rows="6" placeholder='支持格式：
1. JSON格式: {"cookies": {"key": "value"}}
2. 分号分隔: key1=value1; key2=value2
3. 完整cookie: leaflow_session=xxx; remember_xxx=xxx; XSRF-TOKEN=xxx' required></textarea><div class="format-hint">从浏览器开发者工具(F12) → Network → 请求头 → Cookie 复制</div></div>
                <div style="display: flex; gap: 10px; margin-top: 20px;"><button type="button" class="btn btn-full" onclick="updateAccountCookie()">保存修改</button><button type="button" class="btn btn-danger" onclick="closeModal('editAccountModal')">取消</button></div>
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('authToken');

        function showToast(message, type = 'info') {
            const toast = document.getElementById('toast');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 3000);
        }

        function showLoginError(message) {
            const errorDiv = document.getElementById('loginError');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => { errorDiv.style.display = 'none'; }, 5000);
        }

        async function handleLogin() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            if (!username || !password) { showLoginError('请输入用户名和密码'); return; }

            const loginBtn = document.getElementById('loginBtn');
            loginBtn.disabled = true;
            loginBtn.textContent = '登录中...';

            try {
                const response = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
                const data = await response.json();
                if (response.ok && data.token) {
                    authToken = data.token;
                    localStorage.setItem('authToken', authToken);
                    showToast('登录成功', 'success');
                    document.getElementById('loginContainer').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'block';
                    loadDashboard(); loadAccounts(); loadNotificationSettings();
                } else { showLoginError(data.message || '用户名或密码错误'); }
            } catch (error) { showLoginError('登录失败：' + error.message); }
            finally { loginBtn.disabled = false; loginBtn.textContent = '登录'; }
        }

        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('username').addEventListener('keypress', e => { if (e.key === 'Enter') handleLogin(); });
            document.getElementById('password').addEventListener('keypress', e => { if (e.key === 'Enter') handleLogin(); });

            if (authToken) {
                fetch('/api/verify', { headers: { 'Authorization': 'Bearer ' + authToken } }).then(response => {
                    if (response.ok) {
                        document.getElementById('loginContainer').style.display = 'none';
                        document.getElementById('dashboard').style.display = 'block';
                        loadDashboard(); loadAccounts(); loadNotificationSettings();
                    } else { localStorage.removeItem('authToken'); authToken = null; document.getElementById('loginContainer').style.display = 'flex'; document.getElementById('dashboard').style.display = 'none'; }
                }).catch(() => { localStorage.removeItem('authToken'); authToken = null; document.getElementById('loginContainer').style.display = 'flex'; document.getElementById('dashboard').style.display = 'none'; });
            } else { document.getElementById('loginContainer').style.display = 'flex'; document.getElementById('dashboard').style.display = 'none'; }
        });

        function logout() { localStorage.removeItem('authToken'); authToken = null; location.reload(); }

        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(url, { ...options, headers: { 'Authorization': 'Bearer ' + authToken, 'Content-Type': 'application/json', ...options.headers } });
                if (response.status === 401) { logout(); return; }
                const data = await response.json();
                if (!response.ok) throw new Error(data.message || 'Request failed');
                return data;
            } catch (error) { console.error('API call error:', error); throw error; }
        }

        async function loadDashboard() {
            try {
                const data = await apiCall('/api/dashboard');
                if (!data) return;
                document.getElementById('totalAccounts').textContent = data.total_accounts || 0;
                document.getElementById('activeAccounts').textContent = data.enabled_accounts || 0;
                document.getElementById('totalCheckins').textContent = data.total_checkins || 0;
                document.getElementById('successRate').textContent = (data.success_rate || 0) + '%';

                const tbody = document.getElementById('todayCheckins');
                tbody.innerHTML = '';
                if (data.today_checkins && data.today_checkins.length > 0) {
                    data.today_checkins.forEach(checkin => {
                        const tr = document.createElement('tr');
                        const statusText = checkin.success ? '成功' : '失败';
                        const statusClass = checkin.success ? 'badge-success' : 'badge-danger';
                        const time = checkin.created_at ? new Date(checkin.created_at).toLocaleTimeString() : '-';
                        const retryTimes = checkin.retry_times || 0;
                        const retryBadge = retryTimes > 0 ? `<span class="badge badge-info">${retryTimes}</span>` : '-';
                        tr.innerHTML = `<td>${checkin.name || '-'}</td><td><span class="badge ${statusClass}">${statusText}</span></td><td>${checkin.message || '-'}</td><td>${retryBadge}</td><td>${time}</td>`;
                        tbody.appendChild(tr);
                    });
                } else { tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #a0aec0;">暂无记录</td></tr>'; }
            } catch (error) { console.error('Failed to load dashboard:', error); }
        }

        async function loadAccounts() {
            try {
                const accounts = await apiCall('/api/accounts');
                if (!accounts) return;
                const tbody = document.getElementById('accountsList');
                tbody.innerHTML = '';
                if (accounts && accounts.length > 0) {
                    accounts.forEach(account => {
                        const tr = document.createElement('tr');
                        const interval = account.check_interval || 60;
                        const retryCount = account.retry_count || 2;
                        tr.innerHTML = `<td>${account.name}</td><td><label class="switch"><input type="checkbox" ${account.enabled ? 'checked' : ''} onchange="toggleAccount(${account.id}, this.checked)"><span class="slider"></span></label></td><td><div class="time-range-input"><input type="time" value="${account.checkin_time_start || '06:30'}" onchange="updateAccountTime(${account.id}, 'start', this.value)"><span>-</span><input type="time" value="${account.checkin_time_end || '06:40'}" onchange="updateAccountTime(${account.id}, 'end', this.value)"></div></td><td><div class="interval-input"><input type="number" value="${interval}" min="30" max="3600" onchange="updateAccountInterval(${account.id}, this.value)"><span>秒</span></div></td><td><div class="interval-input"><input type="number" value="${retryCount}" min="0" max="5" onchange="updateAccountRetry(${account.id}, this.value)"><span>次</span></div></td><td><button class="btn btn-success btn-sm" onclick="manualCheckin(${account.id})">立即签到</button><button class="btn btn-info btn-sm" onclick="showEditAccountModal(${account.id}, '${account.name}')">修改</button><button class="btn btn-danger btn-sm" onclick="deleteAccount(${account.id})">删除</button></td>`;
                        tbody.appendChild(tr);
                    });
                } else { tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #a0aec0;">暂无账号</td></tr>'; }
            } catch (error) { console.error('Failed to load accounts:', error); }
        }

        async function loadNotificationSettings() {
            try {
                const settings = await apiCall('/api/notification');
                if (!settings) return;
                document.getElementById('notifyEnabled').checked = settings.enabled === true || settings.enabled === 1;
                document.getElementById('telegramEnabled').checked = settings.telegram_enabled === true || settings.telegram_enabled === 1;
                document.getElementById('tgBotToken').value = settings.telegram_bot_token || '';
                document.getElementById('tgUserId').value = settings.telegram_user_id || '';
                document.getElementById('telegramHost').value = settings.telegram_host || '';
                document.getElementById('wechatEnabled').checked = settings.wechat_enabled === true || settings.wechat_enabled === 1;
                document.getElementById('wechatKey').value = settings.wechat_webhook_key || '';
                document.getElementById('wechatHost').value = settings.wechat_host || '';
                document.getElementById('wxpusherEnabled').checked = settings.wxpusher_enabled === true || settings.wxpusher_enabled === 1;
                document.getElementById('wxpusherAppToken').value = settings.wxpusher_app_token || '';
                document.getElementById('wxpusherUid').value = settings.wxpusher_uid || '';
                document.getElementById('wxpusherHost').value = settings.wxpusher_host || '';
                document.getElementById('dingtalkEnabled').checked = settings.dingtalk_enabled === true || settings.dingtalk_enabled === 1;
                document.getElementById('dingtalkAccessToken').value = settings.dingtalk_access_token || '';
                document.getElementById('dingtalkSecret').value = settings.dingtalk_secret || '';
                document.getElementById('dingtalkHost').value = settings.dingtalk_host || '';
            } catch (error) { console.error('Failed to load notification settings:', error); }
        }

        async function toggleAccount(id, enabled) { try { await apiCall(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify({ enabled }) }); loadAccounts(); } catch (error) { showToast('操作失败', 'error'); } }
        async function updateAccountTime(id, type, value) { try { const data = {}; if (type === 'start') data.checkin_time_start = value; else data.checkin_time_end = value; await apiCall(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify(data) }); } catch (error) { showToast('操作失败', 'error'); } }
        async function updateAccountInterval(id, value) { try { await apiCall(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify({ check_interval: parseInt(value) }) }); } catch (error) { showToast('操作失败', 'error'); } }
        async function updateAccountRetry(id, value) { try { await apiCall(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify({ retry_count: parseInt(value) }) }); } catch (error) { showToast('操作失败', 'error'); } }
        async function manualCheckin(id) { if (confirm('确定立即执行签到吗？')) { try { await apiCall(`/api/checkin/manual/${id}`, { method: 'POST' }); showToast('签到任务已触发', 'success'); setTimeout(loadDashboard, 2000); } catch (error) { showToast('操作失败', 'error'); } } }
        async function deleteAccount(id) { if (confirm('确定删除此账号吗？')) { try { await apiCall(`/api/accounts/${id}`, { method: 'DELETE' }); showToast('账号删除成功', 'success'); loadAccounts(); } catch (error) { showToast('操作失败', 'error'); } } }
        async function clearCheckinHistory(type) { const message = type === 'today' ? '确定清空今日签到记录吗？' : '确定清空所有签到记录吗？'; if (confirm(message)) { try { await apiCall('/api/checkin/clear', { method: 'POST', body: JSON.stringify({ type }) }); showToast('清空成功', 'success'); loadDashboard(); } catch (error) { showToast('操作失败: ' + error.message, 'error'); } } }

        async function saveNotificationSettings() {
            try {
                const settings = { enabled: document.getElementById('notifyEnabled').checked, telegram_enabled: document.getElementById('telegramEnabled').checked, telegram_bot_token: document.getElementById('tgBotToken').value, telegram_user_id: document.getElementById('tgUserId').value, telegram_host: document.getElementById('telegramHost').value, wechat_enabled: document.getElementById('wechatEnabled').checked, wechat_webhook_key: document.getElementById('wechatKey').value, wechat_host: document.getElementById('wechatHost').value, wxpusher_enabled: document.getElementById('wxpusherEnabled').checked, wxpusher_app_token: document.getElementById('wxpusherAppToken').value, wxpusher_uid: document.getElementById('wxpusherUid').value, wxpusher_host: document.getElementById('wxpusherHost').value, dingtalk_enabled: document.getElementById('dingtalkEnabled').checked, dingtalk_access_token: document.getElementById('dingtalkAccessToken').value, dingtalk_secret: document.getElementById('dingtalkSecret').value, dingtalk_host: document.getElementById('dingtalkHost').value };
                await apiCall('/api/notification', { method: 'PUT', body: JSON.stringify(settings) });
                showToast('设置保存成功', 'success');
                setTimeout(loadNotificationSettings, 500);
            } catch (error) { showToast('操作失败: ' + error.message, 'error'); }
        }

        async function testNotification() { try { await apiCall('/api/test/notification', { method: 'POST' }); showToast('测试通知已发送', 'info'); } catch (error) { showToast('发送失败: ' + error.message, 'error'); } }

        function showAddAccountModal() { document.getElementById('addAccountModal').style.display = 'flex'; }
        function showEditAccountModal(accountId, accountName) { document.getElementById('editAccountId').value = accountId; document.getElementById('editAccountModal').style.display = 'flex'; }
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
            if (modalId === 'addAccountModal') { document.getElementById('accountName').value = ''; document.getElementById('checkinTimeStart').value = '06:30'; document.getElementById('checkinTimeEnd').value = '06:40'; document.getElementById('checkInterval').value = '60'; document.getElementById('retryCount').value = '2'; document.getElementById('tokenData').value = ''; }
            else if (modalId === 'editAccountModal') { document.getElementById('editAccountId').value = ''; document.getElementById('editTokenData').value = ''; }
        }

        async function addAccount() {
            try {
                const account = { name: document.getElementById('accountName').value, checkin_time_start: document.getElementById('checkinTimeStart').value, checkin_time_end: document.getElementById('checkinTimeEnd').value, check_interval: parseInt(document.getElementById('checkInterval').value), retry_count: parseInt(document.getElementById('retryCount').value), token_data: document.getElementById('tokenData').value };
                if (!account.name || !account.token_data) { showToast('请填写完整信息', 'error'); return; }
                await apiCall('/api/accounts', { method: 'POST', body: JSON.stringify(account) });
                showToast('账号添加成功', 'success');
                closeModal('addAccountModal');
                loadAccounts();
            } catch (error) { showToast('格式无效: ' + error.message, 'error'); }
        }

        async function updateAccountCookie() {
            try {
                const accountId = document.getElementById('editAccountId').value;
                const tokenData = document.getElementById('editTokenData').value;
                if (!tokenData) { showToast('请输入Cookie数据', 'error'); return; }
                await apiCall(`/api/accounts/${accountId}`, { method: 'PUT', body: JSON.stringify({ token_data: tokenData }) });
                showToast('账号修改成功', 'success');
                closeModal('editAccountModal');
                loadAccounts();
            } catch (error) { showToast('修改失败: ' + error.message, 'error'); }
        }

        window.onclick = function(event) { const modals = ['addAccountModal', 'editAccountModal']; modals.forEach(modalId => { const modal = document.getElementById(modalId); if (event.target == modal) closeModal(modalId); }); }
        setInterval(() => { if (authToken && document.getElementById('dashboard').style.display === 'block') loadDashboard(); }, 60000);
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    try:
        scheduler.start()
        logger.info(f"Starting Leaflow Control Panel on port {PORT}")
        logger.info(f"Config directory: {CONFIG_DIR}")
        logger.info(f"Admin username: {ADMIN_USERNAME}")
        logger.info(f"Access the panel at: http://localhost:{PORT}")
        logger.info(f"Timezone: Asia/Shanghai (UTC+8)")
        logger.info(f"Storage: Local JSON config files")
        app.run(host='0.0.0.0', port=PORT, debug=False)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
