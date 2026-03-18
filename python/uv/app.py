from flask import Flask, request, render_template_string
import yaml
import pickle
import subprocess
import xml.etree.ElementTree as ET
from sqlalchemy import create_engine, text
import requests
from cryptography.fernet import Fernet

from jinja2 import Environment as je
from workzeug.utils import secure_filename


app = Flask(__name__)

# Flask SSTI vulnerability (CVE-2019-1010083)
@app.route('/template')
def template():
    user_input = request.args.get('name', '')
    template = f'''
    <h1>Hello {user_input}!</h1>
    '''
    return render_template_string(template)  # Vulnerable to Server-Side Template Injection

# PyYAML Deserialization vulnerability (CVE-2020-14343)
@app.route('/yaml')
def yaml_load():
    yaml_data = request.args.get('data', '')
    return yaml.load(yaml_data)  # Vulnerable to RCE through YAML deserialization

# Pickle Deserialization vulnerability (CVE-2019-12760)
@app.route('/pickle')
def pickle_load():
    data = request.args.get('data', '')
    return pickle.loads(data.encode())  # Vulnerable to RCE through Pickle deserialization

# Command Injection vulnerability
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    return subprocess.check_output(cmd, shell=True)  # Vulnerable to command injection

# XML XXE vulnerability (CVE-2017-18342)
@app.route('/xml')
def xml_parse():
    xml_data = request.args.get('data', '')
    return ET.fromstring(xml_data)  # Vulnerable to XXE

# SQLAlchemy SQL Injection (CVE-2019-7548)
@app.route('/users')
def get_users():
    user_id = request.args.get('id', '')
    engine = create_engine('sqlite:///test.db')
    with engine.connect() as conn:
        query = text(f"SELECT * FROM users WHERE id = {user_id}")  # Vulnerable to SQL injection
        return str(conn.execute(query).fetchall())

# Requests SSRF vulnerability (CVE-2018-18074)
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    return requests.get(url).text  # Vulnerable to SSRF

def encrypt_key(key):
    return Fernet(key)

if __name__ == '__main__':
    je.autoescape = False
    secure_filename('test')
    app.run(debug=True)
