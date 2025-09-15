import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

class TestDataGenerator:
    """Generator for test data"""
    
    @staticmethod
    def generate_show_data(count: int = 10) -> List[Dict[str, Any]]:
        """Generate test show data"""
        shows = []
        base_date = datetime.now()
        
        for i in range(count):
            show_date = base_date + timedelta(days=i)
            show = {
                'artist_show_id': f'test-show-{i+1}',
                'event_date': show_date.strftime('%Y-%m-%d'),
                'venue': {
                    'venue_name': f'Test Venue {i+1}',
                    'city': {
                        'city_name': f'Test City {i+1}',
                        'state': f'TS{i+1}'
                    }
                },
                'songs': TestDataGenerator.generate_song_data(show_date)
            }
            shows.append(show)
        
        return shows

    @staticmethod
    def generate_song_data(show_date: datetime, count: int = 5) -> List[Dict[str, Any]]:
        """Generate test song data"""
        songs = []
        
        for i in range(count):
            song = {
                'song_name': f'Test Song {i+1}',
                'encore': random.choice([True, False]),
                'song': {
                    'cover_artist': {
                        'artist_name': f'Test Artist {i+1}'
                    }
                }
            }
            songs.append(song)
        
        return songs

    @staticmethod
    def generate_search_terms() -> List[Dict[str, str]]:
        """Generate test search terms"""
        return [
            {'term': 'Test', 'action': 'venue'},
            {'term': 'Test', 'action': 'city'},
            {'term': datetime.now().strftime('%Y-%m-%d'), 'action': 'date'},
            {'term': 'Test Song', 'action': 'song'}
        ]

    @staticmethod
    def generate_pagination_params() -> List[Dict[str, int]]:
        """Generate test pagination parameters"""
        return [
            {'page': 1, 'limit': 10},
            {'page': 2, 'limit': 20},
            {'page': 3, 'limit': 5}
        ]

    @staticmethod
    def generate_filter_params() -> List[Dict[str, Any]]:
        """Generate test filter parameters"""
        return [
            {
                'date_from': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
                'date_to': datetime.now().strftime('%Y-%m-%d'),
                'venue_id': 'test-venue-1',
                'city_id': 'test-city-1',
                'encore_only': True,
                'artist_id': 'test-artist-1'
            },
            {
                'date_from': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
                'date_to': datetime.now().strftime('%Y-%m-%d'),
                'venue_id': 'test-venue-2',
                'city_id': 'test-city-2',
                'encore_only': False,
                'artist_id': 'test-artist-2'
            }
        ]

    @staticmethod
    def generate_invalid_params() -> List[Dict[str, Any]]:
        """Generate test invalid parameters"""
        return [
            {'page': 0, 'limit': 10},
            {'page': 1, 'limit': 0},
            {'page': -1, 'limit': 10},
            {'page': 1, 'limit': 1000},
            {'term': '', 'action': 'venue'},
            {'term': 'Test', 'action': ''},
            {'term': 'invalid-date', 'action': 'date'},
            {'date_from': 'invalid-date', 'date_to': '2024-03-20'},
            {'date_from': '2024-03-20', 'date_to': 'invalid-date'}
        ] 