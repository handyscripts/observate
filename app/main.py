import os
import json
from datetime import datetime
from flask_fontawesome import FontAwesome
from flask import Flask, render_template, request, url_for, send_from_directory, redirect, abort
from werkzeug.utils import secure_filename
from models.xmlparser import parse_xml_stats, get_scan_data, get_graph_data

app = Flask(__name__)
FontAwesome(app)

app.config['UPLOAD_FOLDER'] = 'files'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 # 4mb
app.config['FONTAWESOME_STYLES'] = ['all', 'solid', 'brand']
app.config['FONTAWESOME_SERVE_LOCAL'] = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/info')
def about():
   return render_template('info.html')
   
@app.route('/scan/<filename>')
def scan(filename):
    pathname = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    if not os.path.exists(pathname):
        abort(404)
        
    hosts = get_scan_data(pathname)
    if not hosts:
        return render_template('index.html', error_message="Unable to retrieve scan data")
        
    stats = parse_xml_stats(pathname)
    network_nodes, network_edges = get_graph_data(hosts)
    return render_template('scan.html', hosts=hosts, stats=stats, filename=filename)

@app.route('/graph/<filename>')
def browse(filename):
    pathname = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    if not os.path.exists(pathname):
        abort(404)
    hosts = get_scan_data(pathname)
    if not hosts:
        return render_template('index.html', error_message="Unable to retrieve scan data")
    stats = parse_xml_stats(pathname)
    network_nodes, network_edges = get_graph_data(hosts)
    
    return render_template('graph.html', nodes=json.dumps(network_nodes), edges=json.dumps(network_edges), hosts=hosts, filename=filename)

@app.route("/upload", methods=['POST'])
def upload():
    if 'file' not in request.files:
        return render_template('index.html', error_message="'file' parameter not passed to file uploader.")

    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error_message="No File Selected.")
    filename=secure_filename(file.filename)

    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        return render_template('index.html', error_message="Incorrect file type or empty file.")

    return redirect(url_for("scan", filename=filename))

@app.errorhandler(404)
def page_not_found(error):
   return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host="0.0.0.0")