import pytest
from datetime import datetime
from app.database import DatabaseManager, DatabaseError, ConnectionError, QueryError, ValidationError

@pytest.fixture
def db():
    """Fixture to provide a database instance"""
    return DatabaseManager()

@pytest.fixture
def mock_show_data():
    """Fixture to provide mock show data"""
    return {
        'artist_show_id': 'test-show-1',
        'event_date': '2024-03-20',
        'venue': {
            'venue_name': 'Test Venue',
            'city': {
                'city_name': 'Test City',
                'state': 'TS'
            }
        },
        'songs': [
            {
                'song_name': 'Test Song 1',
                'encore': False,
                'song': {
                    'cover_artist': {
                        'artist_name': 'Test Artist'
                    }
                }
            }
        ]
    }

def test_get_shows(db):
    """Test getting shows with pagination"""
    result = db.get_shows(page=1, limit=10)
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)
    assert 'total' in result['pagination']
    assert 'page' in result['pagination']
    assert 'limit' in result['pagination']

def test_get_shows_invalid_page(db):
    """Test getting shows with invalid page number"""
    with pytest.raises(ValidationError):
        db.get_shows(page=0, limit=10)

def test_get_shows_invalid_limit(db):
    """Test getting shows with invalid limit"""
    with pytest.raises(ValidationError):
        db.get_shows(page=1, limit=0)

def test_get_show_by_id(db):
    """Test getting a specific show by ID"""
    # First get a valid show ID
    print("TESTING GET SHOW BY ID")
    shows = db.get_shows(page=1, limit=1)
    print(f"Retrieved shows: {shows}") 
    if shows['data']:
        show_id = shows['data'][0]['artist_show_id']
        result = db.get_show_by_id(show_id)
        print(f"Retrieved show: {result}")  # Debug print
        assert isinstance(result, dict)
        assert 'artist_show_id' in result
        assert 'event_date' in result
        assert 'venue' in result
        assert 'songs' in result

def test_get_show_by_id_invalid(db):
    """Test getting a show with invalid ID"""
    with pytest.raises(ValidationError):
        db.get_show_by_id('')

def test_get_show_by_id_not_found(db):
    """Test getting a non-existent show"""
    with pytest.raises(ValidationError):
        db.get_show_by_id('non-existent-id')

def test_get_artist_shows(db):
    """Test getting shows for a specific artist"""
    # First get a valid artist ID
    shows = db.get_shows(page=1, limit=1)
    if shows['data'] and shows['data'][0]['songs']:
        artist_id = shows['data'][0]['songs'][0]['song']['cover_artist']['artist_name']
        result = db.get_artist_shows(artist_id, page=1, limit=10)
        assert 'data' in result
        assert 'pagination' in result
        assert isinstance(result['data'], list)
        assert isinstance(result['pagination'], dict)

def test_get_artist_shows_invalid_id(db):
    """Test getting shows with invalid artist ID"""
    with pytest.raises(ValidationError):
        db.get_artist_shows('', page=1, limit=10)

def test_search_shows_by_venue(db):
    """Test searching shows by venue"""
    result = db.search_shows(
        term='Test',
        action='venue',
        page=1,
        limit=10
    )
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)

def test_search_shows_by_city(db):
    """Test searching shows by city"""
    result = db.search_shows(
        term='Test',
        action='city',
        page=1,
        limit=10
    )
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)

def test_search_shows_by_date(db):
    """Test searching shows by date"""
    result = db.search_shows(
        term='2024-03-20',
        action='date',
        page=1,
        limit=10
    )
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)

def test_search_shows_invalid_date(db):
    """Test searching shows with invalid date"""
    with pytest.raises(ValidationError):
        db.search_shows(
            term='invalid-date',
            action='date',
            page=1,
            limit=10
        )

def test_search_shows_missing_term(db):
    """Test searching shows without search term"""
    with pytest.raises(ValidationError):
        db.search_shows(
            term='',
            action='venue',
            page=1,
            limit=10
        )

def test_search_shows_missing_action(db):
    """Test searching shows without action"""
    with pytest.raises(ValidationError):
        db.search_shows(
            term='Test',
            action='',
            page=1,
            limit=10
        )

def test_search_songs(db):
    """Test searching songs"""
    result = db.search_songs(
        term='Test',
        page=1,
        limit=10
    )
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)

def test_search_songs_with_filters(db):
    """Test searching songs with filters"""
    result = db.search_songs(
        term='Test',
        page=1,
        limit=10,
        encore_only=True,
        artist_id='test-artist'
    )
    assert 'data' in result
    assert 'pagination' in result
    assert isinstance(result['data'], list)
    assert isinstance(result['pagination'], dict)

def test_search_songs_missing_term(db):
    """Test searching songs without search term"""
    with pytest.raises(ValidationError):
        db.search_songs(
            term='',
            page=1,
            limit=10
        )

def test_get_total_shows(db):
    """Test getting total number of shows"""
    result = db.get_total_shows()
    assert isinstance(result, int)
    assert result >= 0

def test_health_check(db):
    """Test health check endpoint"""
    result = db.health_check()
    assert isinstance(result, dict)
    assert 'postgresql' in result
    assert 'supabase' in result
    assert 'timestamp' in result
    assert 'errors' in result
    assert isinstance(result['errors'], list) 