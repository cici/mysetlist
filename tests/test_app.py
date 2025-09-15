import pytest
from app.api import app
from app.database import DatabaseError, ConnectionError, QueryError, ValidationError

@pytest.fixture
def client():
    """Fixture to provide a test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test the index route"""
    response = client.get('/')
    assert response.status_code == 200

def test_get_shows(client):
    """Test getting shows"""
    response = client.get('/shows?page=1&limit=10')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_get_shows_invalid_page(client):
    """Test getting shows with invalid page"""
    response = client.get('/shows?page=0&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_get_show_by_id(client):
    """Test getting a specific show"""
    # First get a valid show ID
    shows_response = client.get('/shows?page=1&limit=1')
    if shows_response.status_code == 200:
        show_id = shows_response.get_json()['data'][0]['artist_show_id']
        response = client.get(f'/shows/{show_id}')
        assert response.status_code == 200
        data = response.get_json()
        assert 'artist_show_id' in data
        assert 'event_date' in data
        assert 'venue' in data
        assert 'songs' in data

def test_get_show_by_id_invalid(client):
    """Test getting a show with invalid ID"""
    response = client.get('/shows/invalid-id')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_get_artist_shows(client):
    """Test getting shows for a specific artist"""
    # First get a valid artist ID
    shows_response = client.get('/shows?page=1&limit=1')
    if shows_response.status_code == 200:
        show_data = shows_response.get_json()['data'][0]
        if show_data['songs']:
            artist_id = show_data['songs'][0]['song']['cover_artist']['artist_name']
            response = client.get(f'/artists/{artist_id}/shows?page=1&limit=10')
            assert response.status_code == 200
            data = response.get_json()
            assert 'data' in data
            assert 'pagination' in data

def test_get_artist_shows_invalid_id(client):
    """Test getting shows with invalid artist ID"""
    response = client.get('/artists/invalid-id/shows?page=1&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_search_shows_by_venue(client):
    """Test searching shows by venue"""
    response = client.get('/search?term=Test&action=venue&page=1&limit=10')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_search_shows_by_city(client):
    """Test searching shows by city"""
    response = client.get('/search?term=Test&action=city&page=1&limit=10')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_search_shows_by_date(client):
    """Test searching shows by date"""
    response = client.get('/search?term=2024-03-20&action=date&page=1&limit=10')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_search_shows_invalid_date(client):
    """Test searching shows with invalid date"""
    response = client.get('/search?term=invalid-date&action=date&page=1&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_search_shows_missing_term(client):
    """Test searching shows without search term"""
    response = client.get('/search?action=venue&page=1&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_search_shows_missing_action(client):
    """Test searching shows without action"""
    response = client.get('/search?term=Test&page=1&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_search_songs(client):
    """Test searching songs"""
    response = client.get('/search?term=Test&action=song&page=1&limit=10')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_search_songs_with_filters(client):
    """Test searching songs with filters"""
    response = client.get('/search?term=Test&action=song&page=1&limit=10&encore_only=true&artist_id=test-artist')
    assert response.status_code == 200
    data = response.get_json()
    assert 'data' in data
    assert 'pagination' in data

def test_search_songs_missing_term(client):
    """Test searching songs without search term"""
    response = client.get('/search?action=song&page=1&limit=10')
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error']['type'] == 'ValidationError'

def test_get_total_shows(client):
    """Test getting total number of shows"""
    response = client.get('/total-shows')
    assert response.status_code == 200
    data = response.get_json()
    assert 'count' in data
    assert isinstance(data['count'], int)

def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert 'postgresql' in data
    assert 'supabase' in data
    assert 'timestamp' in data
    assert 'errors' in data
    assert isinstance(data['errors'], list) 