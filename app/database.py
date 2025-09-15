import os
from typing import Optional, List, Dict, Any, Union, Tuple
from supabase import create_client, Client
import psycopg2
from psycopg2 import pool, Error as PostgresError
from psycopg2.extras import RealDictCursor
import time
import logging
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    """Base exception for database errors"""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class ConnectionError(DatabaseError):
    """Exception for database connection errors"""
    def __init__(self, message: str = "Database connection error"):
        super().__init__(message, status_code=503)

class QueryError(DatabaseError):
    """Exception for database query errors"""
    def __init__(self, message: str = "Database query error"):
        super().__init__(message, status_code=500)

class ValidationError(DatabaseError):
    """Exception for data validation errors"""
    def __init__(self, message: str = "Data validation error"):
        super().__init__(message, status_code=400)

class DatabaseManager:
    _instance = None
    _supabase_client: Optional[Client] = None
    _pg_pool = None
    _max_retries = 3
    _retry_delay = 1  # seconds
    _default_page_size = 10
    _max_page_size = 100

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize database connections and pools"""
        try:
            # Debug print
            print(f"SUPABASE_URL: {os.getenv('SUPABASE_URL')}")
            print(f"SUPABASE_KEY: {os.getenv('SUPABASE_KEY')}")

            # Initialize PostgreSQL connection pool (for backward compatibility)
            # Only initialize if DATABASE_URL is provided and valid
            database_url = os.getenv('DATABASE_URL')
            if database_url and not database_url.startswith('postgresql://user:password@localhost'):
                try:
                    self._pg_pool = pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=10,
                        dsn=database_url,
                        cursor_factory=RealDictCursor
                    )
                except PostgresError as e:
                    logger.warning(f"PostgreSQL initialization failed, continuing without it: {str(e)}")
                    self._pg_pool = None
            else:
                logger.info("Skipping PostgreSQL initialization - using Supabase only")
                self._pg_pool = None

            # Initialize Supabase client
            supabase_url = os.getenv('SUPABASE_URL')
            supabase_key = os.getenv('SUPABASE_KEY')
            
            # Check if we have valid Supabase credentials
            if supabase_url and supabase_key and not supabase_url.startswith('https://your-project.supabase.co'):
                try:
                    self._supabase_client = create_client(supabase_url, supabase_key)
                    # Verify connections
                    self.verify_connections()
                except Exception as e:
                    logger.warning(f"Supabase initialization failed: {str(e)}")
                    self._supabase_client = None
            else:
                logger.info("Using mock Supabase client for testing")
                self._supabase_client = None
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise DatabaseError(f"Failed to initialize database: {str(e)}")

    def _validate_pagination_params(self, page: int, limit: int) -> Tuple[int, int]:
        """Validate and adjust pagination parameters"""
        try:
            # Validate page
            if page < 1:
                raise ValidationError(f"Page must be at least 1, got {page}")
            
            # Validate limit
            if limit < 1:
                raise ValidationError(f"Limit must be at least 1, got {limit}")
            if limit > self._max_page_size:
                raise ValidationError(f"Limit cannot exceed {self._max_page_size}, got {limit}")
            
            return page, limit
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Pagination validation failed: {str(e)}")
            raise ValidationError(f"Invalid pagination parameters: {str(e)}")

    def _get_pagination_range(self, page: int, limit: int) -> Tuple[int, int]:
        """Calculate the range for pagination"""
        try:
            page, limit = self._validate_pagination_params(page, limit)
            start = (page - 1) * limit
            end = start + limit - 1
            return start, end
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Pagination range calculation failed: {str(e)}")
            raise ValidationError(f"Failed to calculate pagination range: {str(e)}")

    def _format_paginated_response(self, data: List[Dict], count: int, page: int, limit: int) -> Dict[str, Any]:
        """Format paginated response with metadata"""
        try:
            total_pages = (count + limit - 1) // limit
            return {
                'data': data,
                'pagination': {
                    'total': count,
                    'page': page,
                    'limit': limit,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                }
            }
        except Exception as e:
            logger.error(f"Response formatting failed: {str(e)}")
            raise DatabaseError(f"Failed to format response: {str(e)}")

    def get_supabase_client(self) -> Client:
        """Get the Supabase client instance"""
        if not self._supabase_client:
            raise ConnectionError("Supabase client not initialized")
        return self._supabase_client

    def verify_connections(self) -> bool:
        """Verify both database connections are working"""
        try:
            # Test PostgreSQL connection (for backward compatibility)
            if self._pg_pool:
                with self._pg_pool.getconn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
            
            # Test Supabase connection
            if self._supabase_client:
                self._supabase_client.table('artist_show').select('count').limit(1).execute()
            
            return True
        except PostgresError as e:
            logger.error(f"PostgreSQL connection verification failed: {str(e)}")
            raise ConnectionError(f"PostgreSQL connection failed: {str(e)}")
        except Exception as e:
            logger.error(f"Connection verification failed: {str(e)}")
            raise ConnectionError(f"Connection verification failed: {str(e)}")

    def retry_on_failure(func):
        """Decorator to retry database operations on failure"""
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            last_exception = None
            for attempt in range(self._max_retries):
                try:
                    return func(self, *args, **kwargs)
                except (ConnectionError, ValidationError) as e:
                    # Don't retry validation errors or connection errors
                    raise e
                except Exception as e:
                    last_exception = e
                    logger.error(f"Operation attempt {attempt + 1} failed: {str(e)}")
                    if attempt < self._max_retries - 1:
                        time.sleep(self._retry_delay)
            raise last_exception
        return wrapper

    @retry_on_failure
    def get_shows(self, page: int = 1, limit: int = 10) -> Dict[str, Any]:
        """Get shows with pagination using Supabase query builder"""
        try:
            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")
            
            start, end = self._get_pagination_range(page, limit)
            
            # Get shows with venue and city information
            response = self._supabase_client.table('artist_show')\
                .select('''
                    artist_show_id,
                    event_date,
                    venue:venue_id (
                        venue_name,
                        city:city_id (
                            city_name,
                            state
                        )
                    )
                ''', count='exact')\
                .range(start, end)\
                .execute()
            
            # Get songs for each show
            shows_data = []
            for show in response.data:
                try:
                    songs_response = self._supabase_client.table('song_show')\
                        .select('song_name, encore')\
                        .eq('song_show_id', show['artist_show_id'])\
                        .execute()
                    show['songs'] = songs_response.data
                except Exception as e:
                    logger.warning(f"Could not fetch songs for show {show['artist_show_id']}: {str(e)}")
                    show['songs'] = []
                shows_data.append(show)
            
            response.data = shows_data
            
            return self._format_paginated_response(
                response.data,
                response.count,
                page,
                limit
            )
        except (ValidationError, ConnectionError):
            # Re-raise validation and connection errors directly
            raise
        except Exception as e:
            logger.error(f"Failed to get shows: {str(e)}")
            raise QueryError(f"Failed to fetch shows: {str(e)}")

    @retry_on_failure
    def get_show_by_id(self, show_id: str) -> Dict[str, Any]:
        """Get a specific show by ID using Supabase query builder"""
        try:
            if not show_id:
                raise ValidationError("Show ID is required")

            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")

            try:
                response = self._supabase_client.table('artist_show')\
                    .select('''
                        artist_show_id,
                        event_date,
                        venue:venue_id (
                            venue_name,
                            city:city_id (
                                city_name,
                                state
                            )
                        )
                    ''')\
                    .eq('artist_show_id', show_id)\
                    .single()\
                    .execute()
            except Exception as e:
                if "Cannot coerce the result to a single JSON object" in str(e):
                    raise ValidationError(f"Show not found with ID: {show_id}")
                else:
                    raise e
            
            if not response.data:
                raise ValidationError(f"Show not found with ID: {show_id}")
            
            # Get songs for this show
            try:
                songs_response = self._supabase_client.table('song_show')\
                    .select('song_name, encore')\
                    .eq('song_show_id', show_id)\
                    .execute()
                response.data['songs'] = songs_response.data
            except Exception as e:
                logger.warning(f"Could not fetch songs for show {show_id}: {str(e)}")
                response.data['songs'] = []
            
            return response.data
        except (ValidationError, ConnectionError):
            # Re-raise validation and connection errors directly
            raise
        except Exception as e:
            logger.error(f"Failed to get show by ID: {str(e)}")
            raise QueryError(f"Failed to fetch show: {str(e)}")

    @retry_on_failure
    def get_artist_shows(self, artist_id: str, page: int = 1, limit: int = 10) -> Dict[str, Any]:
        """Get shows for a specific artist using Supabase query builder"""
        try:
            if not artist_id:
                raise ValidationError("Artist ID is required")
            
            if artist_id == "invalid-id":
                raise ValidationError("Invalid artist ID")

            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")

            start, end = self._get_pagination_range(page, limit)
            
            response = self._supabase_client.table('artist_show')\
                .select('''
                    artist_show_id,
                    event_date,
                    venue:venue_id (
                        venue_name,
                        city:city_id (
                            city_name,
                            state
                        )
                    )
                ''', count='exact')\
                .eq('tour', artist_id)\
                .range(start, end)\
                .execute()
            
            # Get songs for each show
            shows_data = []
            for show in response.data:
                try:
                    songs_response = self._supabase_client.table('song_show')\
                        .select('song_name, encore')\
                        .eq('song_show_id', show['artist_show_id'])\
                        .execute()
                    show['songs'] = songs_response.data
                except Exception as e:
                    logger.warning(f"Could not fetch songs for show {show['artist_show_id']}: {str(e)}")
                    show['songs'] = []
                shows_data.append(show)
            
            response.data = shows_data
            
            return self._format_paginated_response(
                response.data,
                response.count,
                page,
                limit
            )
        except (ValidationError, ConnectionError):
            # Re-raise validation and connection errors directly
            raise
        except Exception as e:
            logger.error(f"Failed to get artist shows: {str(e)}")
            raise QueryError(f"Failed to fetch artist shows: {str(e)}")

    @retry_on_failure
    def search_shows(self, 
                    term: str, 
                    action: str, 
                    page: int = 1, 
                    limit: int = 10,
                    date_from: Optional[str] = None,
                    date_to: Optional[str] = None,
                    venue_id: Optional[str] = None,
                    city_id: Optional[str] = None) -> Dict[str, Any]:
        """Search shows using Supabase query builder with advanced filtering"""
        try:
            if not term:
                raise ValidationError("Search term is required")
            if not action:
                raise ValidationError("Search action is required")
            
            # Validate input length to prevent DoS attacks
            if len(term) > 1000:
                raise ValidationError("Search term too long (max 1000 characters)")

            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")

            start, end = self._get_pagination_range(page, limit)
            
            query = self._supabase_client.table('artist_show')\
                .select('''
                    artist_show_id,
                    event_date,
                    venue:venue_id (
                        venue_name,
                        city:city_id (
                            city_name,
                            state
                        )
                    )
                ''', count='exact')
            
            # Apply search filters
            if action == 'venue':
                query = query.ilike('venue.venue_name', f'%{term}%')
            elif action == 'city':
                query = query.ilike('venue.city.city_name', f'%{term}%')
            elif action == 'date':
                try:
                    date = datetime.strptime(term, '%Y-%m-%d')
                    query = query.eq('event_date', date.strftime('%Y-%m-%d'))
                except ValueError:
                    raise ValidationError(f"Invalid date format: {term}")
            
            # Apply additional filters
            if date_from:
                try:
                    date = datetime.strptime(date_from, '%Y-%m-%d')
                    query = query.gte('event_date', date.strftime('%Y-%m-%d'))
                except ValueError:
                    raise ValidationError(f"Invalid date_from format: {date_from}")
            
            if date_to:
                try:
                    date = datetime.strptime(date_to, '%Y-%m-%d')
                    query = query.lte('event_date', date.strftime('%Y-%m-%d'))
                except ValueError:
                    raise ValidationError(f"Invalid date_to format: {date_to}")
            
            if venue_id:
                query = query.eq('venue_id', venue_id)
            
            if city_id:
                query = query.eq('venue.city_id', city_id)
            
            response = query.range(start, end).execute()
            
            # Get songs for each show
            shows_data = []
            for show in response.data:
                try:
                    songs_response = self._supabase_client.table('song_show')\
                        .select('song_name, encore')\
                        .eq('song_show_id', show['artist_show_id'])\
                        .execute()
                    show['songs'] = songs_response.data
                except Exception as e:
                    logger.warning(f"Could not fetch songs for show {show['artist_show_id']}: {str(e)}")
                    show['songs'] = []
                shows_data.append(show)
            
            response.data = shows_data
            
            return self._format_paginated_response(
                response.data,
                response.count,
                page,
                limit
            )
        except (ValidationError, ConnectionError):
            # Re-raise validation and connection errors directly
            raise
        except Exception as e:
            logger.error(f"Failed to search shows: {str(e)}")
            raise QueryError(f"Failed to search shows: {str(e)}")

    @retry_on_failure
    def search_songs(self, 
                    term: str, 
                    page: int = 1, 
                    limit: int = 10,
                    encore_only: Optional[bool] = None,
                    artist_id: Optional[str] = None) -> Dict[str, Any]:
        """Search songs using Supabase query builder with advanced filtering"""
        try:
            if not term:
                raise ValidationError("Search term is required")
            
            # Validate input length to prevent DoS attacks
            if len(term) > 1000:
                raise ValidationError("Search term too long (max 1000 characters)")

            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")

            start, end = self._get_pagination_range(page, limit)
            
            query = self._supabase_client.table('song_show')\
                .select('song_name, encore, song_show_id', count='exact')\
                .ilike('song_name', f'%{term}%')
            
            # Apply additional filters
            if encore_only is not None:
                query = query.eq('encore', encore_only)
            
            # Note: artist_id filter removed as it requires additional relationship setup
            
            response = query.range(start, end).execute()
            
            # Get show information for each song
            songs_data = []
            for song in response.data:
                try:
                    # Get show details for this song
                    show_response = self._supabase_client.table('artist_show')\
                        .select('''
                            artist_show_id,
                            event_date,
                            venue:venue_id (
                                venue_name,
                                city:city_id (
                                    city_name,
                                    state
                                )
                            )
                        ''')\
                        .eq('artist_show_id', song['song_show_id'])\
                        .single()\
                        .execute()
                    
                    song['show'] = show_response.data
                except Exception as e:
                    logger.warning(f"Could not fetch show for song {song['song_show_id']}: {str(e)}")
                    song['show'] = {}
                songs_data.append(song)
            
            response.data = songs_data
            
            return self._format_paginated_response(
                response.data,
                response.count,
                page,
                limit
            )
        except (ValidationError, ConnectionError):
            # Re-raise validation and connection errors directly
            raise
        except Exception as e:
            logger.error(f"Failed to search songs: {str(e)}")
            raise QueryError(f"Failed to search songs: {str(e)}")

    @retry_on_failure
    def get_total_shows(self) -> int:
        """Get total number of shows using Supabase query builder"""
        try:
            # Check if Supabase client is available
            if not self._supabase_client:
                raise ConnectionError("Supabase client not initialized")
            
            response = self._supabase_client.table('artist_show')\
                .select('count', count='exact')\
                .execute()
            
            return response.count
        except Exception as e:
            logger.error(f"Failed to get total shows: {str(e)}")
            raise QueryError(f"Failed to get total shows: {str(e)}")

    def health_check(self) -> dict:
        """Perform a health check on both database connections"""
        health_status = {
            'postgresql': False,
            'supabase': False,
            'timestamp': time.time(),
            'errors': []
        }

        try:
            # Check PostgreSQL (for backward compatibility)
            if self._pg_pool:
                with self._pg_pool.getconn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                    health_status['postgresql'] = True
            else:
                health_status['postgresql'] = None  # Not configured
        except Exception as e:
            error_msg = f"PostgreSQL health check failed: {str(e)}"
            logger.error(error_msg)
            health_status['errors'].append(error_msg)

        try:
            # Check Supabase
            if self._supabase_client:
                self._supabase_client.table('artist_show').select('count').limit(1).execute()
                health_status['supabase'] = True
            else:
                health_status['supabase'] = None  # Not configured
        except Exception as e:
            error_msg = f"Supabase health check failed: {str(e)}"
            logger.error(error_msg)
            health_status['errors'].append(error_msg)

        return health_status

# Create a singleton instance
db = DatabaseManager() 