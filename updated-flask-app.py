from flask import Flask, render_template, request, jsonify, send_file
import os
from werkzeug.utils import secure_filename
import networkx as nx
import matplotlib.pyplot as plt
import io
import base64

# ... (previous imports and OneBillionAI class definition)

app = Flask(__name__)
ai_assistant = OneBillionAI()

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    password = data['password']
    if ai_assistant.authenticate(password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False}), 401

@app.route('/query', methods=['POST'])
def query():
    data = request.json
    query = data['query']
    response = ai_assistant.process_query(query)
    return jsonify({'response': response})

@app.route('/process_file', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        if file.content_type.startswith('image/'):
            result = ai_assistant.process_image(file_path)
        elif file.content_type.startswith('audio/'):
            result = ai_assistant.process_audio(file_path)
        else:
            result = "Unsupported file type"
        
        os.remove(file_path)  # Clean up the file after processing
        return jsonify({'result': result})

@app.route('/visualize_network')
def visualize_network():
    G = nx.random_geometric_graph(20, 0.125)
    pos = nx.get_node_attributes(G, "pos")
    
    nodes = [{"x": coord[0], "y": coord[1]} for coord in pos.values()]
    
    return jsonify({'nodes': nodes})

if __name__ == "__main__":
    # Start the scheduled tasks in a separate thread
    threading.Thread(target=ai_assistant.run_scheduled_tasks, daemon=True).start()
    
    # Run the Flask app
    app.run(debug=True)
