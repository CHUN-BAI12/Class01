# Class01 - 用户信息管理平台

简易用户信息管理平台的登录功能，基于 Python Flask 框架。

## 功能

- 用户登录
- 用户信息展示
- 会话管理（登录/登出）

## 快速启动

```bash
pip install flask
python3 app.py
```

访问 http://localhost:5000

## 内置用户

| 用户名 | 密码（哈希存储） | 角色 | 余额 |
|--------|:--------------:|:----:|:----:|
| admin | admin123 | admin | 99999 |
| alice | alice2025 | user | 100 |

> 🔒 本版本已修复密码明文存储、CSRF 缺失、Secret Key 硬编码等安全漏洞。详情参见 `class01.md`。
