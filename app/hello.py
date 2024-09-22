from flask import Flask, render_template, jsonify, make_response, request
import psycopg2
from psycopg2.extras import RealDictCursor
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisa600secretkey#92'

DATABASE_URL = 'postgresql://bcb:uvB4rcXdWk5iWFUQn7ZFwihfJMeGuTlw@dpg-crl2tnqj1k6c73fl0ueg-a.oregon-postgres.render.com/setlist_ldrk'

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
    conn.commit()

    # close the cursor and connection
    cur.close()
    conn.close()

    return render_template('test.html')


@app.route('/shows', methods=['GET'])
def get_shows():

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (limit * page) - limit;

    print(page)
    print(limit)
    print(offset)

    total_shows = getTotalShows()

    #main_query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
    #on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} OFFSET {1}'''.format(limit, offset)

    main_query = createMainQuery(None, None, limit, offset)
    cur.execute(main_query)

    # Fetch the data
    results = cur.fetchall()
    final_results = {}
    show_list = []
    final_results['total_shows'] = total_shows
    index = 0
    for row in results:
        # Append main show information
        show_list.append(dict(row))
        # Get the songs
        artist_show_id = row['artist_show_id']
        with conn.cursor(cursor_factory=RealDictCursor) as song_cursor:
            song_query = '''select ss.song_name, ss.encore, a.artist_name from song_show ss
            left join song s on ss.song_name=s.song_name
            left join artist a on s.cover_artist_id=a.mbid
            where song_show_id='{0}' '''.format(artist_show_id)
            song_cursor.execute(song_query)
            song_list = song_cursor.fetchall()
            show_list[index]['song_list'] = song_list
        index = index + 1
    conn.commit()

    # close the cursor and connection
    cur.close()
    conn.close()
    final_results['show_list'] = show_list
    #print(final_results)
    return final_results
    #return jsonify(data, status=200, mimetype='application/json')
    #return make_response(jsonify(data), 200)

@app.route('/search', methods=['GET'])
def search_shows():

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
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
            song_query = createSongQuery(term, action, artist_show_id)
            song_cursor.execute(song_query)
            song_list = song_cursor.fetchall()
            show_list[index]['song_list'] = song_list
        index = index + 1

    final_results['show_list'] = show_list
    #print(final_results)
    return final_results

def searchBySong(term, action, limit, offset):
    song_query = createSongQuery(term, action, None)

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(song_query)
    # Fetch the data
    results = cur.fetchall()
    final_results = {}
    show_list = []
    # Scroll through list of songs and add shows
    index = 0
    print("Search by Song")
    for row in results:
       print(row['artist_show_id'])
       show_query = createShowQuery(row['artist_show_id'])
    return final_results

def createMainQuery(term, action, limit, offset):
    if action == 'venue':
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id
        where v.venue_name like '%{0}%' LIMIT {1} OFFSET {2}'''.format(term,limit, offset)
    elif action == 'city':
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id
        where c.city_name like '%{0}%' LIMIT {1} OFFSET {2}'''.format(term,limit, offset)
    else:
        query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
        on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} OFFSET {1}'''.format(limit, offset)
    return query

def createSongQuery(term, action, artist_show_id):
    if action == 'song':
        query = '''select show.artist_show_id, ss.song_show_id, ss.song_name, ss.encore, a.artist_name from song_show ss
        left join song s on ss.song_name=s.song_name
        left join artist a on s.cover_artist_id=a.mbid
        left join artist_show show on show.artist_show_id=ss.song_show_id
        where ss.song_name like '%{0}%' '''.format(term)
    else:
        query = '''select ss.song_name, ss.encore, a.artist_name from song_show ss
        left join song s on ss.song_name=s.song_name
        left join artist a on s.cover_artist_id=a.mbid
        where song_show_id='{0}' '''.format(artist_show_id)
    return query

def createShowQuery(artist_show_id):
    query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
    on show.venue_id = v.id left join city c on v.city_id = c.id where show.artist_show_id = '{0}' '''.format(artist_show_id)

    return query

def getTotalShows():
    total_shows_query = '''select count(*) from artist_show'''
    count_cursor = conn.cursor()
    count_cursor.execute(total_shows_query)
    return count_cursor.fetchone()[0]

