# SmartSploit Module Development Guide

## Tổng quan

SmartSploit Framework sử dụng hệ thống module linh hoạt tương tự Metasploit để tổ chức các công cụ khai thác và phân tích smart contract. Mỗi module thuộc một trong 4 loại chính:

- **Exploit Modules**: Các module khai thác lỗ hổng bảo mật
- **Auxiliary Modules**: Các module hỗ trợ (scanner, reconnaissance)  
- **Payload Modules**: Các module tạo mã độc và contract tấn công
- **Post Modules**: Các module post-exploitation sau khi khai thác thành công

## Cấu trúc Module

### Base Classes

Tất cả modules đều kế thừa từ các base class trong `smartsploit/lib/base_module.py`:

```python
from smartsploit.lib.base_module import ExploitModule, ExecutionResult

class MyExploit(ExploitModule):
    def __init__(self):
        super().__init__()
        # Cấu hình module
        
    def run(self):
        # Logic chính của module
        return ExecutionResult(success=True, message="Exploit completed")
```

### Thư mục Module

```
smartsploit/modules/
├── exploits/           # Exploit modules
│   ├── reentrancy/     # Reentrancy exploits
│   ├── overflow/       # Integer overflow exploits
│   ├── access_control/ # Access control exploits
│   ├── defi/          # DeFi-specific exploits
│   └── business_logic/ # Business logic exploits
├── auxiliary/          # Auxiliary modules
│   ├── scanner/        # Contract scanners
│   ├── gather/         # Information gathering
│   └── analysis/       # Static/dynamic analysis
├── payloads/          # Payload generators
│   ├── generic/        # Generic malicious contracts
│   └── specific/       # Target-specific payloads
└── post/              # Post-exploitation
    ├── exfiltration/   # Data extraction
    └── persistence/    # Backdoor maintenance
```

## Phát triển Module

### 1. Exploit Module

```python
from smartsploit.lib.base_module import ExploitModule, ExecutionResult

class MyReentrancyExploit(ExploitModule):
    def __init__(self):
        super().__init__()
        self.name = "exploits/reentrancy/my_exploit"
        self.description = "Mô tả exploit của bạn"
        self.author = "Tên tác giả"
        self.version = "1.0"
        self.rank = "high"  # low, normal, high, excellent
        
        # Các tùy chọn bắt buộc
        self.required_options = ["TARGET_CONTRACT", "RPC_URL"]
        
        # Các tùy chọn mặc định
        self.options = {
            "TARGET_CONTRACT": "",
            "RPC_URL": "http://localhost:8545",
            "GAS_LIMIT": 3000000
        }
    
    def check(self):
        # Kiểm tra điều kiện trước khi chạy
        if not super().check():
            return False
        # Thêm kiểm tra cụ thể cho exploit
        return True
    
    def run(self):
        # Logic chính của exploit
        try:
            # Thực hiện exploit
            result = self.perform_exploit()
            return ExecutionResult(True, "Exploit successful", result)
        except Exception as e:
            return ExecutionResult(False, f"Exploit failed: {str(e)}")
```

### 2. Auxiliary Module (Scanner)

```python
from smartsploit.lib.base_module import AuxiliaryModule, ExecutionResult

class MyScanner(AuxiliaryModule):
    def __init__(self):
        super().__init__()
        self.name = "auxiliary/scanner/my_scanner"
        self.description = "Mô tả scanner của bạn"
        self.scan_type = "scan"  # info, scan, gather
        
        self.required_options = ["TARGET_CONTRACT"]
        self.options = {
            "TARGET_CONTRACT": "",
            "SCAN_DEPTH": "basic"
        }
    
    def run(self):
        # Logic quét và phân tích
        scan_results = self.perform_scan()
        return ExecutionResult(True, "Scan completed", scan_results)
```

### 3. Payload Module

```python
from smartsploit.lib.base_module import PayloadModule, ExecutionResult

class MyPayload(PayloadModule):
    def __init__(self):
        super().__init__()
        self.name = "payloads/generic/my_payload"
        self.description = "Mô tả payload của bạn"
        self.payload_type = "backdoor"
        
        self.required_options = ["ATTACKER_ADDRESS"]
        self.options = {
            "ATTACKER_ADDRESS": "",
            "PAYLOAD_TYPE": "backdoor"
        }
    
    def generate(self):
        # Tạo mã Solidity độc hại
        contract_code = """
        pragma solidity ^0.8.19;
        contract MaliciousContract {
            // Payload code here
        }
        """
        return contract_code
```

### 4. Post-Exploitation Module

```python
from smartsploit.lib.base_module import PostModule, ExecutionResult

class MyPostExploit(PostModule):
    def __init__(self):
        super().__init__()
        self.name = "post/exfiltration/my_post"
        self.description = "Mô tả post-exploitation"
        self.session_type = "contract"
        
        self.required_options = ["TARGET_CONTRACT", "SESSION_ID"]
        self.options = {
            "TARGET_CONTRACT": "",
            "SESSION_ID": "",
            "EXTRACT_DATA": True
        }
    
    def run(self):
        # Logic post-exploitation
        extracted_data = self.extract_contract_data()
        return ExecutionResult(True, "Data extracted", extracted_data)
```

## Module Registration

Mỗi module phải có function `get_module()` để framework có thể load:

```python
def get_module():
    return MyExploitClass()
```

## Sử dụng Module trong Console

### Các lệnh cơ bản:

```bash
# Tìm kiếm module
search reentrancy

# Sử dụng module
use exploits/reentrancy/classic

# Xem thông tin module
info

# Xem các tùy chọn
show options

# Thiết lập tùy chọn
set TARGET_CONTRACT 0x1234567890123456789012345678901234567890
set RPC_URL https://mainnet.infura.io/v3/YOUR_KEY

# Kiểm tra điều kiện
check

# Chạy module
run
```

### Auxiliary Module:
```bash
use auxiliary/scanner/contract_info
set TARGET_CONTRACT 0x...
run
```

### Payload Module:
```bash
use payloads/generic/backdoor_contract
set ATTACKER_ADDRESS 0x...
set PAYLOAD_TYPE backdoor
run
```

### Post-Exploitation:
```bash
use post/exfiltration/contract_data
set TARGET_CONTRACT 0x...
set SESSION_ID session_123
run
```

## Best Practices

### 1. Error Handling
- Luôn sử dụng try-catch trong method `run()`
- Trả về ExecutionResult với thông tin lỗi chi tiết
- Log lỗi để debugging

### 2. Validation
- Implement method `check()` để validate options
- Kiểm tra format địa chỉ contract (0x + 40 hex chars)
- Validate network connections

### 3. Documentation
- Mô tả rõ ràng chức năng module
- Liệt kê các targets phù hợp
- Thêm references đến tài liệu kỹ thuật

### 4. Logging
```python
import logging
logger = logging.getLogger(__name__)

def run(self):
    logger.info("Starting exploit...")
    logger.debug("Debug information")
    logger.error("Error occurred")
```

### 5. Framework Integration
```python
def run(self):
    # Sử dụng framework reference
    if self.framework:
        blockchain = self.framework.blockchain_interface
        session = self.framework.session_manager.create_session()
```

## Testing Module

### Kiểm tra cú pháp:
```bash
python -m py_compile smartsploit/modules/exploits/my_module.py
```

### Test trong console:
```bash
# Trong SmartSploit console
reload_modules
use exploits/my_category/my_module
info
check
```

## Demo Modules

Framework đi kèm các demo modules để tham khảo:

- `exploits/reentrancy/demo_reentrancy.py` - Template cho reentrancy exploit
- `auxiliary/scanner/demo_scanner.py` - Template cho contract scanner  
- `payloads/generic/demo_payload.py` - Template cho payload generator
- `post/exfiltration/demo_exfiltration.py` - Template cho post-exploitation

Các demo modules này cung cấp cấu trúc chuẩn và có thể chạy được để test framework.

## Troubleshooting

### Module không load được:
- Kiểm tra syntax errors
- Đảm bảo có function `get_module()`
- Kiểm tra đường dẫn file

### Lỗi khi chạy module:
- Kiểm tra method `check()` 
- Validate các required options
- Xem logs để debug

### Performance issues:
- Optimize blockchain calls
- Use caching cho repeated queries
- Implement timeouts cho network operations