from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1>Test Shop App</h1>
    <ul>
        <li><a href="/products/1">Product 1</a></li>
        <li><a href="/products/55">Product 55 (Same pattern)</a></li>
        <li><a href="/users/profile">User Profile</a></li>
        <li><a href="/api/v1/status">API Status</a></li>
    </ul>
    """

@app.route('/products/<int:prod_id>')
def get_product(prod_id):
    return jsonify({
        "id": prod_id, 
        "name": f"Super Item #{prod_id}", 
        "price": 100 + prod_id
    })

@app.route('/users/profile')
def profile():
    return "User Profile Page (Sensitive Info)"

@app.route('/api/v1/search')
def search():
    query = request.args.get('q', 'nothing')
    return jsonify({"result": f"You searched for: {query}"})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        return f"Welcome back, {user}!"
    return '<form method="POST"><input name="username"><button>Login</button></form>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)