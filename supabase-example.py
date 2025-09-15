from supabase import create_client, Client
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_shows():
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        term = request.args.get('term')
        action = request.args.get('action')
        offset = (limit * page) - limit

        # Build base query
        query = supabase.table('artist_show')\
            .select('''
                artist_show_id,
                event_date,
                venue:venue_id (
                    venue_name,
                    city:city_id (
                        city_name,
                        state
                    )
                ),
                song_show:song_show_id (
                    song_name,
                    encore,
                    song:song_name (
                        artist:cover_artist_id (
                            artist_name
                        )
                    )
                )
            ''')\
            .range(offset, offset + limit - 1)

        # Add search conditions
        if action == 'venue':
            query = query.ilike('venue.venue_name', f'%{term}%')
        elif action == 'city':
            query = query.ilike('venue.city.city_name', f'%{term}%')
        elif action == 'song':
            query = query.ilike('song_show.song_name', f'%{term}%')

        # Execute query
        response = query.execute()
        
        # Format response
        results = {
            'show_list': response.data
        }

        return jsonify(results)

    except Exception as e:
        # Log error
        app.logger.error(f"Error in search_shows: {str(e)}")
        
        # Return error response
        return jsonify({
            'error': 'An error occurred while processing your request'
        }), 500

# Example of how to handle connection errors
def handle_connection_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log error
            app.logger.error(f"Connection error: {str(e)}")
            
            # Retry logic could be added here
            
            # Return error response
            return jsonify({
                'error': 'Database connection error'
            }), 503
    return wrapper

if __name__ == '__main__':
    app.run(debug=True) 