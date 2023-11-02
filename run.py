# Run a test server.
from paineis_bsb import app
from waitress import serve
# app.run(host='0.0.0.0', port=5000, debug=True)


serve(app, host='127.0.0.1', port=8000)