"""
Web UI Routes for SmartSploit Framework
"""

import json
import time
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from smartsploit.core.framework import get_framework, ExploitResult
from smartsploit.lib.ml_detector import MLVulnerabilityDetector
from models import db, FrameworkStats, Session, ExploitResult as DBExploitResult, VulnerabilityTarget

main_bp = Blueprint('main', __name__)

# Initialize framework
framework = get_framework()
ml_detector = MLVulnerabilityDetector()

@main_bp.route('/')
def dashboard():
    """Main dashboard page"""
    # Get or create framework stats
    stats = FrameworkStats.query.first()
    if not stats:
        stats = FrameworkStats(
            active_modules=len(framework.module_manager.list_modules()),
            successful_exploits=43,
            active_sessions=framework.session_manager.get_session_count(),
            high_risk_contracts=23,
            medium_risk_contracts=47,
            low_risk_contracts=156
        )
        db.session.add(stats)
        db.session.commit()
    
    # Recent exploits (placeholder data)
    recent_exploits = []
    
    # Network status
    network_status = framework.blockchain.get_network_status()
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_exploits=recent_exploits,
                         network_status=network_status)

@main_bp.route('/modules')
def modules():
    """Modules listing page"""
    module_type = request.args.get('type', 'exploit')
    modules = framework.module_manager.list_modules(module_type)
    
    # Get module info for each module
    module_info = []
    for module_path in modules:
        # For demo, create mock module info
        parts = module_path.split('/')
        module_info.append({
            'path': module_path,
            'name': parts[-1].replace('_', ' ').title(),
            'category': parts[0] if len(parts) > 0 else 'unknown',
            'subcategory': parts[1] if len(parts) > 1 else '',
            'severity': 'high' if 'reentrancy' in module_path else 'medium',
            'reliability': 0.85 if 'reentrancy' in module_path else 0.70,
            'description': f"Exploit module for {parts[-1].replace('_', ' ')}"
        })
    
    return render_template('modules.html', 
                         modules=module_info, 
                         current_type=module_type)

@main_bp.route('/console')
def console_interface():
    """Web-based console interface"""
    return render_template('console.html')

@main_bp.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')

@main_bp.route('/sessions')
def sessions():
    """Sessions page"""
    # Get active sessions from framework
    active_sessions = framework.session_manager.list_active_sessions()
    
    # Get session history from database
    db_sessions = Session.query.order_by(Session.created_at.desc()).limit(50).all()
    
    return render_template('sessions.html', 
                         active_sessions=active_sessions,
                         db_sessions=db_sessions)

@main_bp.route('/monitoring')
def monitoring():
    """Monitoring page"""
    from datetime import datetime
    
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
    
    # Get recent exploit results
    recent_results = DBExploitResult.query.order_by(DBExploitResult.created_at.desc()).limit(20).all()
    
    # Get vulnerability targets
    targets = VulnerabilityTarget.query.order_by(VulnerabilityTarget.last_scanned.desc()).limit(10).all()
    
    # Network status
    network_status = framework.blockchain.get_network_status()
    
    # Current time for logs
    current_time = datetime.now()
    
    return render_template('monitoring.html', 
                         stats=stats,
                         recent_results=recent_results,
                         targets=targets,
                         network_status=network_status,
                         current_time=current_time)

@main_bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@main_bp.route('/api/use_module', methods=['POST'])
def use_module():
    """Use/select a module"""
    data = request.get_json()
    module_path = data.get('module_path')
    
    if not module_path:
        return jsonify({'success': False, 'message': 'Module path required'})
    
    success = framework.use_module(module_path)
    
    if success:
        info = framework.show_info()
        options = framework.show_options()
        return jsonify({
            'success': True, 
            'module_info': info,
            'options': options
        })
    else:
        return jsonify({'success': False, 'message': 'Module not found'})

@main_bp.route('/api/set_option', methods=['POST'])
def set_option():
    """Set module option"""
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key:
        return jsonify({'success': False, 'message': 'Option key required'})
    
    framework.set_option(key.upper(), value)
    return jsonify({'success': True})

@main_bp.route('/api/run_module', methods=['POST'])
def run_module():
    """Run current module"""
    if not framework.current_module:
        return jsonify({'success': False, 'message': 'No module selected'})
    
    start_time = time.time()
    result = framework.run_current_module()
    execution_time = time.time() - start_time
    
    # Save result to database
    if hasattr(result, 'get') and result.get('result'):
        db_result = DBExploitResult(
            session_id='web_session',
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

@main_bp.route('/api/scan_contract', methods=['POST'])
def scan_contract():
    """Scan contract for vulnerabilities"""
    data = request.get_json()
    address = data.get('address')
    
    if not address:
        return jsonify({'success': False, 'message': 'Contract address required'})
    
    # Use vulnerability scanner
    scanner_module = framework.module_manager.get_module('auxiliary/scanner/vulnerability')
    if scanner_module:
        scanner_module.set_option('TARGET', address)
        result = scanner_module.run()
        
        # Save to database
        if result.get('result') == 'success' or result.get('result') == ExploitResult.SUCCESS:
            scan_data = result.get('data', {})
            target = VulnerabilityTarget(
                address=address,
                network='mainnet',
                vulnerability_score=scan_data.get('risk_score', 0.0),
                vulnerabilities=json.dumps(scan_data.get('vulnerabilities', {}))
            )
            db.session.add(target)
            db.session.commit()
        
        return jsonify({'success': True, 'scan_result': result})
    else:
        return jsonify({'success': False, 'message': 'Scanner module not available'})

@main_bp.route('/api/console_command', methods=['POST'])
def console_command():
    """Execute console command"""
    data = request.get_json()
    command = data.get('command', '').strip()
    
    if not command:
        return jsonify({'success': False, 'output': 'No command provided'})
    
    # Simple command parsing
    parts = command.split()
    cmd = parts[0].lower()
    
    output = []
    
    try:
        if cmd == 'help':
            output = [
                'Available commands:',
                '  use <module>     - Select a module',
                '  show <type>      - Show modules/options/sessions',
                '  set <opt> <val>  - Set option value',
                '  run              - Execute current module',
                '  search <query>   - Search modules',
                '  info             - Show module info'
            ]
        
        elif cmd == 'use' and len(parts) > 1:
            module_path = parts[1]
            if framework.use_module(module_path):
                output = [f'[+] Using module: {module_path}']
                info = framework.show_info()
                if info:
                    output.append(f"Module: {info['name']}")
                    output.append(f"Description: {info['description']}")
            else:
                output = [f'[-] Module not found: {module_path}']
        
        elif cmd == 'show' and len(parts) > 1:
            show_type = parts[1].lower()
            if show_type == 'exploits':
                modules = framework.module_manager.list_modules('exploit')
                output = ['Exploit Modules:', '=' * 20]
                for i, module in enumerate(modules, 1):
                    output.append(f'{i:3}. {module}')
            elif show_type == 'options':
                options = framework.show_options()
                output = ['Module Options:', '=' * 20]
                for key, value in options.items():
                    output.append(f'{key:<20} {str(value)}')
            else:
                output = [f'[-] Unknown show type: {show_type}']
        
        elif cmd == 'set' and len(parts) > 2:
            key, value = parts[1].upper(), ' '.join(parts[2:])
            framework.set_option(key, value)
            output = [f'[+] {key} => {value}']
        
        elif cmd == 'run':
            if framework.current_module:
                output = ['[*] Running module...']
                result = framework.run_current_module()
                if result.get('result') == 'success' or result.get('result') == ExploitResult.SUCCESS:
                    output.append('[+] Module executed successfully')
                    if 'message' in result:
                        output.append(f'Message: {result["message"]}')
                else:
                    output.append('[-] Module execution failed')
                    if 'message' in result:
                        output.append(f'Error: {result["message"]}')
            else:
                output = ['[-] No module selected']
        
        elif cmd == 'info':
            info = framework.show_info()
            if info:
                output = [
                    'Module Information:',
                    '=' * 20,
                    f'Name: {info["name"]}',
                    f'Description: {info["description"]}',
                    f'Author: {info["author"]}',
                    f'Severity: {info["severity"]}'
                ]
            else:
                output = ['[-] No module selected']
        
        elif cmd == 'search' and len(parts) > 1:
            query = parts[1]
            results = framework.search_modules(query)
            output = [f'Search results for "{query}":']
            for i, module in enumerate(results, 1):
                output.append(f'{i:3}. {module}')
        
        else:
            output = [f'[-] Unknown command: {command}']
    
    except Exception as e:
        output = [f'[-] Command error: {str(e)}']
    
    return jsonify({'success': True, 'output': output})

@main_bp.route('/api/stats')
def get_stats():
    """Get current framework statistics"""
    stats = FrameworkStats.query.first()
    if stats:
        return jsonify({
            'active_modules': stats.active_modules,
            'successful_exploits': stats.successful_exploits,
            'active_sessions': stats.active_sessions,
            'high_risk_contracts': stats.high_risk_contracts,
            'medium_risk_contracts': stats.medium_risk_contracts,
            'low_risk_contracts': stats.low_risk_contracts
        })
    else:
        return jsonify({
            'active_modules': 0,
            'successful_exploits': 0,
            'active_sessions': 0,
            'high_risk_contracts': 0,
            'medium_risk_contracts': 0,
            'low_risk_contracts': 0
        })

@main_bp.route('/api/network_status')
def get_network_status():
    """Get blockchain network status"""
    return jsonify(framework.blockchain.get_network_status())
