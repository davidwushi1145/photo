from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from back import read_json, TRANSACTIONS_FILE, write_json, log_audit

# Flask App 初始化
app = Flask(__name__)
CORS(app)

# 数据库配置（请根据你的 MySQL 用户名、密码、数据库名进行替换）
from urllib.parse import quote_plus

password = quote_plus("lqp1018@")
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{password}@localhost:3306/cross'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 数据模型定义
class Participant(db.Model):
    id = db.Column(db.String(128), primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    country = db.Column(db.String(10), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    verification_date = db.Column(db.DateTime, nullable=True)

class Transaction(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    sender_id = db.Column(db.String(32), db.ForeignKey('participant.id'), nullable=False)
    receiver_id = db.Column(db.String(32), db.ForeignKey('participant.id'), nullable=False)
    data_type = db.Column(db.String(64), nullable=False)
    data_hash = db.Column(db.String(64), nullable=False)
    data_size = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(16), nullable=False)
    compliance_check = db.Column(db.String(255), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(128), nullable=False)
    details = db.Column(db.Text, nullable=False)

class ComplianceRule(db.Model):
    id = db.Column(db.String(128), primary_key=True)
    country = db.Column(db.String(10), nullable=False)
    prohibited_types = db.Column(db.Text)  # 逗号分隔
    allowed_types = db.Column(db.Text)     # 逗号分隔

# 初始化数据库
def setup_database():
    db.create_all()
    if not ComplianceRule.query.first():
        rules = [
            ComplianceRule(country="CN", prohibited_types="个人敏感数据,金融核心数据", allowed_types="地理信息数据,公开统计数据"),
            ComplianceRule(country="US", prohibited_types="", allowed_types="个人数据,金融数据,地理信息数据"),
            ComplianceRule(country="EU", prohibited_types="军事数据", allowed_types="个人数据,金融数据"),
        ]
        db.session.add_all(rules)
        db.session.commit()

# 工具函数
def generate_id(prefix=""):
    return prefix + uuid.uuid4().hex[:16]

def check_compliance(sender_country, receiver_country, data_type):
    sender_rule = ComplianceRule.query.filter_by(country=sender_country).first()
    receiver_rule = ComplianceRule.query.filter_by(country=receiver_country).first()

    if not sender_rule or not receiver_rule:
        return False, "合规规则缺失"

    if data_type in (sender_rule.prohibited_types or "").split(','):
        return False, f"发送方禁止传输数据类型：{data_type}"
    if receiver_rule.allowed_types and data_type not in receiver_rule.allowed_types.split(','):
        return False, f"接收方不允许接收数据类型：{data_type}"

    return True, "合规通过"

def log_action(action, details):
    log = AuditLog(id=generate_id("LOG"), action=action, details=details)
    db.session.add(log)
    db.session.commit()

# 接口：获取所有主体
@app.route('/api/participants', methods=['GET'])
def list_participants():
    participants = Participant.query.all()
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "country": p.country,
        "is_verified": p.is_verified,
        "registration_date": p.registration_date.isoformat(),
        "verification_date": p.verification_date.isoformat() if p.verification_date else None
    } for p in participants])

# 接口：注册主体
@app.route('/api/participants', methods=['POST'])
def register_participant():
    data = request.get_json()
    name = data.get('name')
    country = data.get('country')
    if not name or not country:
        return jsonify({"success": False, "error": "缺少参数"}), 400

    if Participant.query.filter_by(name=name).first():
        return jsonify({"success": False, "error": "主体已存在"}), 409

    new_participant = Participant(id=generate_id("P"), name=name, country=country)
    db.session.add(new_participant)
    db.session.commit()
    log_action("注册主体", f"{name}（{country}）注册")
    return jsonify({"success": True, "id": new_participant.id})

# 接口：认证主体
@app.route('/api/participants/<participant_id>/verify', methods=['POST'])
def verify_participant(participant_id):
    participant = Participant.query.get(participant_id)
    if not participant:
        return jsonify({"success": False, "error": "主体不存在"}), 404

    participant.is_verified = True
    participant.verification_date = datetime.utcnow()
    db.session.commit()
    log_action("认证主体", f"{participant.name} 认证通过")
    return jsonify({"success": True})

@app.route('/api/transactions/<transaction_id>/approve', methods=['PUT'])
def approve_transaction(transaction_id):
    tx = Transaction.query.get(transaction_id)

    if not tx:
        return jsonify({"error": "未找到指定交易"}), 404

    if tx.status == "APPROVED":
        return jsonify({"error": "交易已批准，无法重复审批"}), 400
    if tx.status == "REJECTED":
        return jsonify({"error": "交易已拒绝，无法审批"}), 400
    if tx.status != "PENDING":
        return jsonify({"error": "只能审批待处理状态的交易"}), 400

    tx.status = "APPROVED"
    db.session.commit()

    log_action(
        "审批通过交易",
        f"审批通过交易: {tx.id}, 类型: {tx.data_type}, 大小: {tx.data_size}"
    )

    return jsonify({
        "id": tx.id,
        "status": tx.status
    })


@app.route('/api/transactions/<transaction_id>/reject', methods=['PUT'])
def reject_transaction(transaction_id):
    data = request.json
    reason = data.get("reason")

    if not reason:
        return jsonify({"error": "必须提供拒绝原因"}), 400

    tx = Transaction.query.get(transaction_id)
    if not tx:
        return jsonify({"error": "未找到指定交易"}), 404

    if tx.status == "REJECTED":
        return jsonify({"error": "交易已拒绝，不能重复拒绝"}), 400
    if tx.status == "APPROVED":
        return jsonify({"error": "交易已批准，不能拒绝"}), 400
    if tx.status != "PENDING":
        return jsonify({"error": "只能拒绝待处理状态的交易"}), 400

    tx.status = "REJECTED"
    tx.timestamp = datetime.utcnow()

    db.session.commit()

    log_action(
        "拒绝交易",
        f"拒绝交易: {tx.id} - 原因: {reason}"
    )

    return jsonify({
        "id": tx.id,
        "status": tx.status,
        "reason": reason,
        "message": "交易已被拒绝"
    })




# 接口：提交数据传输请求
@app.route('/api/transactions', methods=['POST'])
def submit_transaction():
    data = request.get_json()
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    data_type = data.get('data_type')
    data_hash = data.get('data_hash')
    data_size = data.get('data_size')

    sender = Participant.query.get(sender_id)
    receiver = Participant.query.get(receiver_id)

    if not sender or not receiver:
        return jsonify({"success": False, "error": "主体不存在"}), 404
    if not sender.is_verified or not receiver.is_verified:
        return jsonify({"success": False, "error": "主体未认证"}), 403

    ok, message = check_compliance(sender.country, receiver.country, data_type)
    # 不自动根据合规结果决定状态，统一先设为PENDING
    status = "PENDING"

    tx = Transaction(
        id=generate_id("TX"),
        sender_id=sender_id,
        receiver_id=receiver_id,
        data_type=data_type,
        data_hash=data_hash,
        data_size=data_size,
        status=status,
        compliance_check=message
    )
    db.session.add(tx)
    db.session.commit()

    log_action("数据传输请求", f"{sender.name} -> {receiver.name}, 类型：{data_type}，合规结果：{message}")
    return jsonify({"success": True, "status": status, "message": message})


# 接口：获取所有传输记录
@app.route('/api/transactions', methods=['GET'])
def list_transactions():
    txs = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return jsonify([{
        "id": tx.id,
        "sender_id": tx.sender_id,
        "receiver_id": tx.receiver_id,
        "data_type": tx.data_type,
        "data_hash": tx.data_hash,
        "data_size": tx.data_size,
        "timestamp": tx.timestamp.isoformat(),
        "status": tx.status,
        "compliance_check": tx.compliance_check
    } for tx in txs])

# 接口：获取审计日志
@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return jsonify([{
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "action": log.action,
        "details": log.details
    } for log in logs])

# 启动 Flask 服务
if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        setup_database()