from app import app, db
from flask import render_template
from werkzeug.exceptions import InternalServerError

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(InternalServerError)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500