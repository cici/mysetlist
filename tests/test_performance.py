"""
Performance tests for the database layer.
Tests query execution times, connection pooling, and concurrent requests.
"""

import pytest
import time
import threading
import concurrent.futures
from app.database import db, ValidationError, ConnectionError
from app.api import app


class TestPerformance:
    """Performance testing suite"""
    
    def test_query_execution_times(self):
        """Test that queries execute within acceptable time limits"""
        # Test get_shows performance
        start_time = time.time()
        result = db.get_shows(page=1, limit=10)
        get_shows_time = time.time() - start_time
        
        assert get_shows_time < 2.0, f"get_shows took {get_shows_time:.2f}s, expected < 2.0s"
        assert 'data' in result
        assert 'pagination' in result
        
        # Test search_songs performance
        start_time = time.time()
        result = db.search_songs(term='Follow', page=1, limit=5)
        search_songs_time = time.time() - start_time
        
        assert search_songs_time < 3.0, f"search_songs took {search_songs_time:.2f}s, expected < 3.0s"
        assert 'data' in result
        assert 'pagination' in result
        
        # Test get_total_shows performance
        start_time = time.time()
        count = db.get_total_shows()
        total_shows_time = time.time() - start_time
        
        assert total_shows_time < 1.0, f"get_total_shows took {total_shows_time:.2f}s, expected < 1.0s"
        assert isinstance(count, int)
        assert count > 0
        
        print(f"Performance metrics:")
        print(f"  get_shows: {get_shows_time:.3f}s")
        print(f"  search_songs: {search_songs_time:.3f}s")
        print(f"  get_total_shows: {total_shows_time:.3f}s")
    
    def test_concurrent_requests(self):
        """Test handling of concurrent database requests"""
        def make_request():
            """Make a database request"""
            try:
                result = db.get_shows(page=1, limit=5)
                return result
            except Exception as e:
                return {"error": str(e)}
        
        # Test with 10 concurrent requests
        num_requests = 10
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_time = time.time() - start_time
        
        # All requests should succeed
        successful_requests = [r for r in results if 'error' not in r]
        assert len(successful_requests) == num_requests, f"Expected {num_requests} successful requests, got {len(successful_requests)}"
        
        # Should complete within reasonable time (allowing for network overhead)
        assert total_time < 10.0, f"Concurrent requests took {total_time:.2f}s, expected < 10.0s"
        
        print(f"Concurrent requests: {num_requests} requests completed in {total_time:.3f}s")
        print(f"Average time per request: {total_time/num_requests:.3f}s")
    
    def test_large_result_set_performance(self):
        """Test performance with larger result sets"""
        # Test with larger page size
        start_time = time.time()
        result = db.get_shows(page=1, limit=50)
        large_page_time = time.time() - start_time
        
        assert large_page_time < 5.0, f"Large page (50 items) took {large_page_time:.2f}s, expected < 5.0s"
        assert len(result['data']) <= 50
        assert result['pagination']['total'] > 0
        
        print(f"Large result set (50 items): {large_page_time:.3f}s")
    
    def test_search_performance_variations(self):
        """Test performance of different search types"""
        search_tests = [
            ('venue', 'Red Rocks'),
            ('city', 'Morrison'),
            ('date', '2024-09-07'),
            ('song', 'Follow')
        ]
        
        results = {}
        
        for search_type, term in search_tests:
            start_time = time.time()
            
            if search_type == 'song':
                result = db.search_songs(term=term, page=1, limit=10)
            else:
                result = db.search_shows(term=term, action=search_type, page=1, limit=10)
            
            execution_time = time.time() - start_time
            results[search_type] = execution_time
            
            assert execution_time < 3.0, f"{search_type} search took {execution_time:.2f}s, expected < 3.0s"
            assert 'data' in result
        
        print("Search performance by type:")
        for search_type, exec_time in results.items():
            print(f"  {search_type}: {exec_time:.3f}s")
    
    def test_pagination_performance(self):
        """Test performance across different pages"""
        page_times = []
        
        # Test first few pages
        for page in [1, 2, 3, 10, 50]:
            start_time = time.time()
            result = db.get_shows(page=page, limit=10)
            page_time = time.time() - start_time
            
            page_times.append((page, page_time))
            assert page_time < 2.0, f"Page {page} took {page_time:.2f}s, expected < 2.0s"
            assert 'data' in result
        
        print("Pagination performance:")
        for page, exec_time in page_times:
            print(f"  Page {page}: {exec_time:.3f}s")
    
    def test_connection_health_under_load(self):
        """Test connection health during load"""
        # Get initial health status
        initial_health = db.health_check()
        assert initial_health['supabase'] == True
        assert len(initial_health['errors']) == 0
        
        # Make multiple requests to stress the connection
        for _ in range(20):
            db.get_shows(page=1, limit=5)
            db.search_songs(term='test', page=1, limit=5)
        
        # Check health after load
        final_health = db.health_check()
        assert final_health['supabase'] == True
        assert len(final_health['errors']) == 0
        
        print("Connection health maintained under load ✓")
    
    def test_memory_usage_stability(self):
        """Test that memory usage remains stable during repeated operations"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many operations
        for i in range(100):
            db.get_shows(page=1, limit=5)
            if i % 10 == 0:  # Check memory every 10 iterations
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_increase = current_memory - initial_memory
                
                # Memory increase should be reasonable (less than 50MB)
                assert memory_increase < 50, f"Memory increased by {memory_increase:.1f}MB, expected < 50MB"
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        total_increase = final_memory - initial_memory
        
        print(f"Memory usage: Initial {initial_memory:.1f}MB, Final {final_memory:.1f}MB, Increase {total_increase:.1f}MB")
        assert total_increase < 50, f"Total memory increase {total_increase:.1f}MB, expected < 50MB"


class TestAPIPerformance:
    """API-level performance tests"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_api_response_times(self, client):
        """Test API endpoint response times"""
        endpoints = [
            '/shows?page=1&limit=10',
            '/shows/23ab94df',
            '/search?term=Red Rocks&action=venue&page=1&limit=10',
            '/search?term=Follow&action=song&page=1&limit=10',
            '/total-shows',
            '/health'
        ]
        
        results = {}
        
        for endpoint in endpoints:
            start_time = time.time()
            response = client.get(endpoint)
            response_time = time.time() - start_time
            
            results[endpoint] = response_time
            assert response.status_code == 200, f"Endpoint {endpoint} returned {response.status_code}"
            assert response_time < 3.0, f"Endpoint {endpoint} took {response_time:.2f}s, expected < 3.0s"
        
        print("API endpoint performance:")
        for endpoint, exec_time in results.items():
            print(f"  {endpoint}: {exec_time:.3f}s")
    
    def test_api_concurrent_requests(self, client):
        """Test API handling of concurrent requests"""
        def make_api_request():
            """Make an API request with its own client context"""
            try:
                with app.test_client() as test_client:
                    response = test_client.get('/shows?page=1&limit=5')
                    return response.status_code == 200
            except Exception:
                return False
        
        # Test with 10 concurrent API requests (reduced to avoid context issues)
        num_requests = 10
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(make_api_request) for _ in range(num_requests)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_time = time.time() - start_time
        
        # All requests should succeed
        successful_requests = sum(results)
        assert successful_requests == num_requests, f"Expected {num_requests} successful requests, got {successful_requests}"
        
        # Should complete within reasonable time
        assert total_time < 15.0, f"Concurrent API requests took {total_time:.2f}s, expected < 15.0s"
        
        print(f"Concurrent API requests: {num_requests} requests completed in {total_time:.3f}s")
        print(f"Average time per request: {total_time/num_requests:.3f}s")
