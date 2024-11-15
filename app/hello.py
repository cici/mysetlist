from flask import Flask, render_template, jsonify, make_response, request
import psycopg2
from psycopg2.extras import RealDictCursor
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisa600secretkey#92'

# DATABASE_URL = 'postgresql://bcb:uvB4rcXdWk5iWFUQn7ZFwihfJMeGuTlw@dpg-crl2tnqj1k6c73fl0ueg-a.oregon-postgres.render.com/setlist_ldrk'

DATABASE_URL = 'postgresql://postgres.psbyspxiwxxryshboqwj:Ihr0LYFSJcQ5jfYU@aws-0-us-east-1.pooler.supabase.com:6543/postgres'

conn = psycopg2.connect(DATABASE_URL)

@app.route('/')
def hello():
    # Connect to the database
    #conn = psycopg2.connect(database="setlist", user="postgres",
    #                        password="root", host="localhost", port="5432")

    # create a cursor
    cur = conn.cursor()

    cur.execute("SELECT * from artist;")

     # Fetch the data
    data = cur.fetchall()
    #print(data)


    return render_template('test.html')


@app.route('/shows', methods=['GET'])
def get_shows():

    final_results = {}

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    offset = (limit * page) - limit;

    #total_shows = getTotalShows()
    #final_results['total_shows'] = total_shows

    main_query = createMainQuery(None, None, limit, offset)
    cur.execute(main_query)

    # Fetch the data
    results = cur.fetchall()

    show_list = populateShowList(results)

    final_results['show_list'] = show_list
    #print(final_results)
    return final_results

@app.route('/search', methods=['GET'])
def search_shows():

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    term = request.args.get('term')
    action = request.args.get('action')
    offset = (limit * page) - limit;

    if action == 'song':
        searchResults = searchBySong(term, action, limit, offset)
    else:
        searchResults = searchByTerm(term, action, limit, offset)


    return searchResults

def searchByTerm(term, action, limit, offset):
    main_query = createMainQuery(term, action, limit, offset)

    # Execute first query
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(main_query)

    print(main_query)

    # Fetch the data
    results = cur.fetchall()
    final_results = {}
    show_list = []

    # Scroll through list of shows and add songs
    index = 0
    for row in results:
        # Append main show information
        show_list.append(dict(row))
        # Get the songs
        artist_show_id = row['artist_show_id']
        with conn.cursor(cursor_factory=RealDictCursor) as song_cursor:
            song_query = createSongQuery(term, action, artist_show_id, limit, offset)
            song_cursor.execute(song_query)
            song_list = song_cursor.fetchall()
            show_list[index]['song_list'] = song_list
        index = index + 1

    final_results['show_list'] = show_list
    #print(final_results)
    return final_results

def searchBySong(term, action, limit, offset):
    song_query = createSongQuery(term, action, None, limit, offset)

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(song_query)

    # Fetch the data
    results = cur.fetchall()
    final_results = {}
    show_list = []

    # Scroll through list of songs and add shows (and their songs)
    show_list = populateShowList(results)
    final_results['show_list'] = show_list
    return final_results


def populateShowList(results):
    show_list = []

    index = 0
    for row in results:
        # Append main show information
        show_list.append(dict(row))
        # Get the songs
        artist_show_id = row['artist_show_id']
        with conn.cursor(cursor_factory=RealDictCursor) as song_cursor:
            song_query = '''select ss.song_name, ss.encore, a.artist_name, count(*) OVER() AS full_count from song_show ss
            left join song s on ss.song_name=s.song_name
            left join artist a on s.cover_artist_id=a.mbid
            where song_show_id='{0}' '''.format(artist_show_id)
            song_cursor.execute(song_query)
            song_list = song_cursor.fetchall()
            show_list[index]['song_list'] = song_list
        index = index + 1
    return show_list
    #return jsonify(data, status=200, mimetype='application/json')
    #return make_response(jsonify(data), 200)

def createMainQuery(term, action, limit, offset):
    if action == 'venue':
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state, count(*) OVER() AS full_count from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id
        where LOWER(v.venue_name) like LOWER('%{0}%') LIMIT {1} OFFSET {2}'''.format(term,limit, offset)
    elif action == 'city':
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state, count(*) OVER() AS full_count from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id
        where LOWER(c.city_name) like LOWER('%{0}%') LIMIT {1} OFFSET {2}'''.format(term,limit, offset)
    else:
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state, count(*) OVER() AS full_count from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} OFFSET {1}'''.format(limit, offset)
    return query

def createSongQuery(term, action, artist_show_id, limit, offset):
    if action == 'song':
        query = '''select show.artist_show_id, show.event_date, v.venue_name, c.city_name, c.state, ss.song_name, ss.encore, a.artist_name, count(*) OVER() AS full_count
        from artist_show show
        left join venue v on show.venue_id = v.id
        left join city c on v.city_id = c.id
        left join song_show ss on show.artist_show_id = ss.song_show_id
        left join song s on ss.song_name=s.song_name
        left join artist a on s.cover_artist_id=a.mbid
        where LOWER(ss.song_name) like LOWER('%{0}%') LIMIT {1} OFFSET {2}'''.format(term, limit, offset)
    else:
        query = '''select ss.song_name, ss.encore, a.artist_name, count(*) OVER() AS full_count from song_show ss
        left join song s on ss.song_name=s.song_name
        left join artist a on s.cover_artist_id=a.mbid
        where song_show_id='{0}' '''.format(artist_show_id)
    return query

def createShowQuery(artist_show_id):
    query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state, count(*) OVER() AS full_count from artist_show show left join venue v
    on show.venue_id = v.id left join city c on v.city_id = c.id where show.artist_show_id = '{0}' '''.format(artist_show_id)

    return query

def createSearchBySongQuery(term):
    query = '''select show.artist_show_id, show.event_date, v.venue_name, c.city_name, c.state, ss.song_name, ss.encore, a.artist_name, count(*) OVER() AS full_count
    from artist_show show
    left join venue v on show.venue_id = v.id
    left join city c on v.city_id = c.id
    left join song_show ss on show.artist_show_id = ss.song_show_id
    left join song s on ss.song_name=s.song_name
    left join artist a on s.cover_artist_id=a.mbid
    where LOWER(ss.song_name) like LOWER('%{0}%') '''.format(term)

    return query

def getTotalShows():
    total_shows_query = '''select count(*) from artist_show'''
    count_cursor = conn.cursor()
    count_cursor.execute(total_shows_query)
    return count_cursor.fetchone()[0]

