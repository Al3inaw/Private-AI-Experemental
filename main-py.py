from flask import Flask, render_template, request, jsonify
from ai_assistant.core import OneBillionAI

app = Flask(__name__)
ai_assistant = OneBillionAI()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/query', methods=['POST'])
def query():
    data = request.json
    query = data['query']
    response = ai_assistant.process_query(query)
    return jsonify({'response': response})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    username = data['username']
    password = data['password']
    if ai_assistant.authenticate(username, password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False}), 401

if __name__ == '__main__':
    app.run(debug=True)
