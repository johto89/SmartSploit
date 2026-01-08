"""
SmartSploit REST API Routes
RESTful API endpoints for the SmartSploit framework
"""

import json
import time
from flask import Blueprint, request, jsonify, current_app
from smartsploit.core.framework import get_framework, ExploitResult
from smartsploit.lib.ml_detector import MLVulnerabilityDetector
from smartsploit.lib.contract_analyzer import ContractAnalyzer
from models import db, FrameworkStats, Session, ExploitResult as DBExploitResult, VulnerabilityTarget

api_bp = Blueprint('api', __name__)

# Initialize components
framework = get_framework()
ml_detector = MLVulnerabilityDetector()
contract_analyzer = ContractAnalyzer()

@api_bp.route('/status', methods=['GET'])
def api_status():
    """Get API status and framework information"""
    return jsonify({
        'status': 'online',
        'framework_version': framework.version,
        'active_modules': len(framework.module_manager.list_modules()),
        'current_module': type(framework.current_module).__name__ if framework.current_module else None,
        'active_sessions': framework.session_manager.get_session_count()
    })

@api_bp.route('/modules', methods=['GET'])
def list_modules():
    """List available modules"""
    module_type = request.args.get('type')
    modules = framework.module_manager.list_modules(module_type)
    
    module_data = []
    for module_path in modules:
        # Get module instance for info
        module = framework.module_manager.get_module(module_path)
        if module and hasattr(module, 'info'):
            info = module.info
            module_data.append({
                'path': module_path,
                'name': info.name,
                'description': info.description,
                'author': info.author,
                'severity': info.severity,
                'reliability': info.reliability,
                'targets': info.targets,
                'references': info.references
            })
        else:
            # Fallback for modules without info
            parts = module_path.split('/')
            module_data.append({
                'path': module_path,
                'name': parts[-1].replace('_', ' ').title(),
                'description': f"Module for {parts[-1].replace('_', ' ')}",
                'author': 'SmartSploit Team',
                'severity': 'medium',
                'reliability': 0.75,
                'targets': [],
                'references': []
            })
    
    return jsonify({
        'success': True,
        'modules': module_data,
        'total': len(module_data)
    })

@api_bp.route('/modules/<path:module_path>/use', methods=['POST'])
def use_module(module_path):
    """Use/select a specific module"""
    success = framework.use_module(module_path)
    
    if success:
        info = framework.show_info()
        options = framework.show_options()
        return jsonify({
            'success': True,
            'module_info': info,
            'options': options,
            'required_options': framework.current_module.required_options if framework.current_module else []
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Module not found: {module_path}'
        }), 404

@api_bp.route('/modules/current/info', methods=['GET'])
def current_module_info():
    """Get information about currently selected module"""
    if not framework.current_module:
        return jsonify({
            'success': False,
            'error': 'No module selected'
        }), 400
    
    info = framework.show_info()
    options = framework.show_options()
    
    return jsonify({
        'success': True,
        'module_info': info,
        'options': options,
        'required_options': framework.current_module.required_options
    })

@api_bp.route('/modules/current/options', methods=['POST'])
def set_module_option():
    """Set option for current module"""
    data = request.get_json()
    
    if not data or 'key' not in data or 'value' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing key or value in request'
        }), 400
    
    key = data['key'].upper()
    value = data['value']
    
    # Type conversion
    if isinstance(value, str):
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '').replace('-', '').isdigit():
            try:
                value = float(value)
            except ValueError:
                pass
    
    framework.set_option(key, value)
    
    return jsonify({
        'success': True,
        'key': key,
        'value': value
    })

@api_bp.route('/modules/current/run', methods=['POST'])
def run_current_module():
    """Execute current module"""
    if not framework.current_module:
        return jsonify({
            'success': False,
            'error': 'No module selected'
        }), 400
    
    # Validate required options
    if not framework.current_module.validate_options():
        missing_options = [
            opt for opt in framework.current_module.required_options
            if opt not in framework.current_module.options or framework.current_module.options[opt] is None
        ]
        return jsonify({
            'success': False,
            'error': 'Missing required options',
            'missing_options': missing_options
        }), 400
    
    start_time = time.time()
    result = framework.run_current_module()
    execution_time = time.time() - start_time
    
    # Save result to database
    if result.get('result'):
        db_result = DBExploitResult(
            session_id='api_session',
            result_status=str(result['result']),
            data=json.dumps(result.get('data', {})),
            execution_time=execution_time
        )
        db.session.add(db_result)
        db.session.commit()
    
    return jsonify({
        'success': True,
        'result': result,
        'execution_time': execution_time
    })

@api_bp.route('/scan/contract', methods=['POST'])
def scan_contract():
    """Scan contract for vulnerabilities"""
    data = request.get_json()
    
    if not data or 'address' not in data:
        return jsonify({
            'success': False,
            'error': 'Contract address required'
        }), 400
    
    address = data['address']
    network = data.get('network', 'mainnet')
    deep_scan = data.get('deep_scan', True)
    
    try:
        # Get contract info
        target = framework.blockchain.get_contract_info(address, network)
        if not target:
            return jsonify({
                'success': False,
                'error': 'Contract not found or invalid address'
            }), 404
        
        # Perform vulnerability scan
        scan_results = {
            'contract_address': address,
            'network': network,
            'scan_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'vulnerabilities': {},
            'risk_score': 0.0,
            'risk_level': 'LOW'
        }
        
        # Use vulnerability scanner module
        scanner = framework.module_manager.get_module('auxiliary/scanner/vulnerability')
        if scanner:
            scanner.set_option('TARGET', address)
            scanner.set_option('NETWORK', network)
            scanner.set_option('DEEP_SCAN', deep_scan)
            
            result = scanner.run()
            if result.get('result') in ['success', ExploitResult.SUCCESS]:
                scan_results.update(result.get('data', {}))
        
        # Save scan results to database
        existing_target = VulnerabilityTarget.query.filter_by(address=address).first()
        if existing_target:
            existing_target.vulnerability_score = scan_results['risk_score']
            existing_target.vulnerabilities = json.dumps(scan_results['vulnerabilities'])
            existing_target.last_scanned = db.func.now()
        else:
            new_target = VulnerabilityTarget(
                address=address,
                network=network,
                vulnerability_score=scan_results['risk_score'],
                vulnerabilities=json.dumps(scan_results['vulnerabilities'])
            )
            db.session.add(new_target)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'scan_results': scan_results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Scan failed: {str(e)}'
        }), 500

@api_bp.route('/targets', methods=['GET'])
def list_targets():
    """List scanned vulnerability targets"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    risk_level = request.args.get('risk_level')
    
    query = VulnerabilityTarget.query
    
    if risk_level:
        if risk_level.upper() == 'HIGH':
            query = query.filter(VulnerabilityTarget.vulnerability_score >= 0.7)
        elif risk_level.upper() == 'MEDIUM':
            query = query.filter(VulnerabilityTarget.vulnerability_score.between(0.4, 0.7))
        elif risk_level.upper() == 'LOW':
            query = query.filter(VulnerabilityTarget.vulnerability_score < 0.4)
    
    targets = query.order_by(VulnerabilityTarget.vulnerability_score.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    target_data = []
    for target in targets.items:
        vulnerabilities = json.loads(target.vulnerabilities) if target.vulnerabilities else {}
        target_data.append({
            'id': target.id,
            'address': target.address,
            'network': target.network,
            'vulnerability_score': target.vulnerability_score,
            'risk_level': 'HIGH' if target.vulnerability_score >= 0.7 else 'MEDIUM' if target.vulnerability_score >= 0.4 else 'LOW',
            'vulnerabilities': vulnerabilities,
            'last_scanned': target.last_scanned.isoformat() if target.last_scanned else None,
            'balance': target.balance
        })
    
    return jsonify({
        'success': True,
        'targets': target_data,
        'pagination': {
            'page': page,
            'pages': targets.pages,
            'per_page': per_page,
            'total': targets.total,
            'has_next': targets.has_next,
            'has_prev': targets.has_prev
        }
    })

@api_bp.route('/sessions', methods=['GET'])
def list_sessions():
    """List active exploit sessions"""
    sessions_data = framework.session_manager.list_active_sessions()
    
    return jsonify({
        'success': True,
        'sessions': [
            {
                'id': session['id'],
                'target_address': session['target'].address,
                'network': session['target'].network,
                'exploit': session['exploit'],
                'status': session['status'],
                'created_at': session['created_at'].isoformat() if hasattr(session['created_at'], 'isoformat') else str(session['created_at'])
            }
            for session in sessions_data
        ],
        'total': len(sessions_data)
    })

@api_bp.route('/sessions/<session_id>', methods=['DELETE'])
def close_session(session_id):
    """Close an active session"""
    success = framework.session_manager.close_session(session_id)
    
    if success:
        return jsonify({
            'success': True,
            'message': f'Session {session_id} closed'
        })
    else:
        return jsonify({
            'success': False,
            'error': f'Session {session_id} not found'
        }), 404

@api_bp.route('/stats', methods=['GET'])
def get_framework_stats():
    """Get framework statistics"""
    stats = FrameworkStats.query.first()
    
    if not stats:
        # Create default stats
        stats = FrameworkStats(
            active_modules=len(framework.module_manager.list_modules()),
            successful_exploits=0,
            active_sessions=framework.session_manager.get_session_count(),
            high_risk_contracts=0,
            medium_risk_contracts=0,
            low_risk_contracts=0
        )
        db.session.add(stats)
        db.session.commit()
    
    # Update dynamic stats
    stats.active_modules = len(framework.module_manager.list_modules())
    stats.active_sessions = framework.session_manager.get_session_count()
    
    # Update contract counts from database
    high_risk = VulnerabilityTarget.query.filter(VulnerabilityTarget.vulnerability_score >= 0.7).count()
    medium_risk = VulnerabilityTarget.query.filter(VulnerabilityTarget.vulnerability_score.between(0.4, 0.7)).count()
    low_risk = VulnerabilityTarget.query.filter(VulnerabilityTarget.vulnerability_score < 0.4).count()
    
    stats.high_risk_contracts = high_risk
    stats.medium_risk_contracts = medium_risk
    stats.low_risk_contracts = low_risk
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'stats': {
            'active_modules': stats.active_modules,
            'successful_exploits': stats.successful_exploits,
            'active_sessions': stats.active_sessions,
            'high_risk_contracts': stats.high_risk_contracts,
            'medium_risk_contracts': stats.medium_risk_contracts,
            'low_risk_contracts': stats.low_risk_contracts,
            'total_contracts': high_risk + medium_risk + low_risk
        }
    })

@api_bp.route('/network/status', methods=['GET'])
def get_network_status():
    """Get blockchain network status"""
    status = framework.blockchain.get_network_status()
    
    return jsonify({
        'success': True,
        'networks': status,
        'total_networks': len(status),
        'online_networks': sum(1 for online in status.values() if online)
    })

@api_bp.route('/monitoring/data', methods=['GET'])
def get_monitoring_data():
    """Get real-time monitoring data"""
    try:
        # Get current stats
        stats = FrameworkStats.query.first()
        if not stats:
            stats = FrameworkStats(
                active_modules=len(framework.module_manager.list_modules()),
                successful_exploits=0,
                active_sessions=framework.session_manager.get_session_count(),
                high_risk_contracts=0,
                medium_risk_contracts=0,
                low_risk_contracts=0
            )
            db.session.add(stats)
            db.session.commit()
        
        # Get recent activity
        recent_results = DBExploitResult.query.order_by(DBExploitResult.created_at.desc()).limit(10).all()
        recent_scans = VulnerabilityTarget.query.order_by(VulnerabilityTarget.last_scanned.desc()).limit(10).all()
        
        # Network status
        network_status = framework.blockchain.get_network_status()
        
        # Active sessions
        active_sessions = framework.session_manager.list_active_sessions()
        
        return jsonify({
            'success': True,
            'timestamp': time.time(),
            'stats': {
                'active_modules': stats.active_modules,
                'successful_exploits': stats.successful_exploits,
                'active_sessions': len(active_sessions),
                'high_risk_contracts': stats.high_risk_contracts,
                'medium_risk_contracts': stats.medium_risk_contracts,
                'low_risk_contracts': stats.low_risk_contracts
            },
            'network_status': network_status,
            'recent_activity': {
                'exploits': [
                    {
                        'id': result.id,
                        'session_id': result.session_id,
                        'status': result.result_status,
                        'execution_time': result.execution_time,
                        'created_at': result.created_at.isoformat() if result.created_at else None
                    }
                    for result in recent_results
                ],
                'scans': [
                    {
                        'id': scan.id,
                        'address': scan.address,
                        'network': scan.network,
                        'risk_score': scan.vulnerability_score,
                        'last_scanned': scan.last_scanned.isoformat() if scan.last_scanned else None
                    }
                    for scan in recent_scans
                ]
            },
            'active_sessions': [
                {
                    'id': session['id'],
                    'target': session['target'].address if hasattr(session.get('target'), 'address') else 'Unknown',
                    'exploit': session.get('exploit', 'Unknown'),
                    'status': session.get('status', 'Unknown'),
                    'created_at': session['created_at'].isoformat() if hasattr(session.get('created_at'), 'isoformat') else str(session.get('created_at', ''))
                }
                for session in active_sessions
            ]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get monitoring data: {str(e)}'
        }), 500

@api_bp.route('/ml/train', methods=['POST'])
def train_ml_models():
    """Train ML vulnerability detection models"""
    data = request.get_json()
    training_data_path = data.get('training_data_path', 'smartsploit/data/training_data.csv')
    
    try:
        ml_detector.train_models(training_data_path)
        return jsonify({
            'success': True,
            'message': 'ML models trained successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Training failed: {str(e)}'
        }), 500

@api_bp.route('/search', methods=['GET'])
def search_modules():
    """Search modules by query"""
    query = request.args.get('q', '')
    
    if not query:
        return jsonify({
            'success': False,
            'error': 'Search query required'
        }), 400
    
    results = framework.search_modules(query)
    
    return jsonify({
        'success': True,
        'query': query,
        'results': results,
        'total': len(results)
    })

# Error handlers
@api_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({
        'success': False,
        'error': 'API endpoint not found'
    }), 404

@api_bp.errorhandler(500)
def api_internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500
