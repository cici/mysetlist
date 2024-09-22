from flask import Flask, render_template, jsonify, make_response, request
import psycopg2
from psycopg2.extras import RealDictCursor
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisa600secretkey#92'


@app.route('/')
def hello():
    # Connect to the database
    #conn = psycopg2.connect(database="setlist", user="postgres",
    #                        password="root", host="localhost", port="5432")

    DATABASE_URL = 'postgresql://bcb:uvB4rcXdWk5iWFUQn7ZFwihfJMeGuTlw@dpg-crl2tnqj1k6c73fl0ueg-a.oregon-postgres.render.com/setlist_ldrk'

    conn = psycopg2.connect(DATABASE_URL)

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
    # Connect to the database
    #conn = psycopg2.connect(database="setlist", user="postgres",
    #                        password="root", host="localhost", port="5432")

    DATABASE_URL = 'postgresql://bcb:uvB4rcXdWk5iWFUQn7ZFwihfJMeGuTlw@dpg-crl2tnqj1k6c73fl0ueg-a.oregon-postgres.render.com/setlist_ldrk'

    conn = psycopg2.connect(DATABASE_URL)

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (limit * page) - limit;

    print(page)
    print(limit)
    print(offset)

#    main_query = '''select row_to_json(row)
#from (select show.event_date, v.venue_name, c.city_name, c.state from #artist_show show left join venue v
#    on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} #OFFSET {1}) row;'''.format(limit, offset)

    total_shows_query = '''select count(*) from artist_show'''
    count_cursor = conn.cursor()
    count_cursor.execute(total_shows_query)
    total_shows = count_cursor.fetchone()[0]

    main_query = '''select show.artist_show_id, show.event_date, v.venue_name,  c.city_name, c.state from artist_show show left join venue v
    on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} OFFSET {1}'''.format(limit, offset)

    cur.execute(main_query)

    # Fetch the data
    results = cur.fetchall()
    final_results = {}
    show_list = []
    show_dict = {}
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
            #final_results['show'] = row
            #final_results['song_list'] = song_list
            #print(song_list)
            #show_songs = song_cursor.fetchall()
            # Convert to dictionary
            #song_dict = jsonify(show_songs)
            #print(song_dict)
            #row_dict['songs'] = jsonify(show_songs)
            #print(song_dict)
        #song_data = get_associated_songs(artist_show_id)
        # Add song data to resultset
        #row_dict['song_data'] = song_data
        #print(row_dict)
        index = index + 1
    conn.commit()

    # close the cursor and connection
    cur.close()
    conn.close()
    print(show_list)
    final_results['show_list'] = show_list
    #print(final_results)
    return final_results
    #return jsonify(data, status=200, mimetype='application/json')
    #return make_response(jsonify(data), 200)

def get_associated_songs(artist_show_id):
    DATABASE_URL = 'postgresql://bcb:uvB4rcXdWk5iWFUQn7ZFwihfJMeGuTlw@dpg-crl2tnqj1k6c73fl0ueg-a.oregon-postgres.render.com/setlist_ldrk'

    conn = psycopg2.connect(DATABASE_URL)

    # create a cursor
    cur = conn.cursor(cursor_factory=RealDictCursor)

    song_query = '''select ss.song_name, ss.encore, a.artist_name from song_show ss
 left join song s on ss.song_name=s.song_name
 left join artist a on s.cover_artist_id=a.mbid
 where song_show_id='{0}' '''.format(artist_show_id)

    cur.execute(song_query)

    # Fetch the data
    results = cur.fetchall()
    #print('song results for id ')
    #print(artist_show_id)
    #print(results)

    # close the cursor and connection
    cur.close()
    conn.close()
    return results

