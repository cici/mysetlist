from flask import Flask, render_template, jsonify, make_response, request
import json
import os
import logging
from dotenv import load_dotenv
from .database import db, DatabaseError, ConnectionError, QueryError, ValidationError, RateLimitError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Flask configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['ENV'] = os.getenv('ENV', 'development')

# Error handlers
@app.errorhandler(DatabaseError)
def handle_database_error(error):
    response = {
        'error': {
            'message': error.message,
            'type': error.__class__.__name__
        }
    }
    return jsonify(response), error.status_code

@app.errorhandler(RateLimitError)
def handle_rate_limit_error(error):
    """Handle rate limiting errors with user-friendly response"""
    response = {
        'error': {
            'message': error.message,
            'type': 'RateLimitError',
            'retry_after': 60,  # Suggest retry after 60 seconds
            'code': 'RATE_LIMIT_EXCEEDED'
        }
    }
    return jsonify(response), 429

@app.errorhandler(Exception)
def handle_generic_error(error):
    response = {
        'error': {
            'message': str(error),
            'type': 'InternalServerError'
        }
    }
    return jsonify(response), 500

@app.route('/')
def index():
    """Home route - displays the main application interface"""
    # Get artists using Supabase
    response = db.get_supabase_client().table('artist').select('*').execute()
    return render_template('test.html')

@app.route('/shows', methods=['GET'])
def get_shows():
    """Get shows with pagination and graceful error handling for rate limiting"""
    try:
        logger.info("Inside shows endpoint")
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        logger.info(f"Fetching shows - page: {page}, limit: {limit}")
        
        # The database layer will handle rate limiting and other errors
        result = db.get_shows(page=page, limit=limit)
        
        logger.info(f"Successfully fetched {len(result.get('data', []))} shows")
        return jsonify(result)
        
    except RateLimitError as e:
        # Rate limit errors are handled by the error handler, but we log them here for monitoring
        logger.warning(f"Rate limit exceeded for /shows endpoint: {str(e)}")
        raise  # Re-raise to let the error handler deal with it
        
    except (ValidationError, ConnectionError, QueryError) as e:
        # Other database errors are also handled by error handlers
        logger.error(f"Database error in /shows endpoint: {str(e)}")
        raise  # Re-raise to let the error handler deal with it
        
    except Exception as e:
        # Catch any unexpected errors
        logger.error(f"Unexpected error in /shows endpoint: {str(e)}")
        raise  # Re-raise to let the generic error handler deal with it

@app.route('/shows/<show_id>', methods=['GET'])
def get_show(show_id):
    return jsonify(db.get_show_by_id(show_id))

@app.route('/artists/<artist_id>/shows', methods=['GET'])
def get_artist_shows(artist_id):
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    return jsonify(db.get_artist_shows(artist_id=artist_id, page=page, limit=limit))

@app.route('/search', methods=['GET'])
def search_shows():
    # Get basic search parameters
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    term = request.args.get('term')
    action = request.args.get('action')

    # Get advanced filter parameters
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    venue_id = request.args.get('venue_id')
    city_id = request.args.get('city_id')
    encore_only = request.args.get('encore_only')
    artist_id = request.args.get('artist_id')

    # Convert encore_only to boolean if provided
    if encore_only is not None:
        encore_only = encore_only.lower() == 'true'

    if action == 'song':
        return jsonify(db.search_songs(
            term=term,
            page=page,
            limit=limit,
            encore_only=encore_only,
            artist_id=artist_id
        ))
    else:
        return jsonify(db.search_shows(
            term=term,
            action=action,
            page=page,
            limit=limit,
            date_from=date_from,
            date_to=date_to,
            venue_id=venue_id,
            city_id=city_id
        ))

@app.route('/total-shows', methods=['GET'])
def get_total_shows():
    return jsonify({'count': db.get_total_shows()})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify(db.health_check())

