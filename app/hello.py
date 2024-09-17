from flask import Flask, render_template, jsonify, make_response, request
import psycopg2


app = Flask(__name__)


@app.route('/')
def hello():
    # Connect to the database
    conn = psycopg2.connect(database="setlist", user="postgres",
                            password="root", host="localhost", port="5432")

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
    conn = psycopg2.connect(database="setlist", user="postgres",
                            password="root", host="localhost", port="5432")

    # create a cursor
    cur = conn.cursor()

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (limit * page) - limit;

    print(page)
    print(limit)
    print(offset)

    main_query = '''select show.event_date, v.venue_name, c.city_name, c.state from artist_show show left join venue v
    on show.venue_id = v.id left join city c on v.city_id = c.id LIMIT {0} OFFSET {1}'''.format(limit, offset)

    cur.execute(main_query)

    # Fetch the data
    data = cur.fetchall()
    #print(data)
    conn.commit()

    # close the cursor and connection
    cur.close()
    conn.close()

    return make_response(jsonify(data), 200)


