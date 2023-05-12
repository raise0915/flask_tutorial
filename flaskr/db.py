import sqlite3

import click
from flask import current_app, g
# gはリクエストごとに個別なobject
# current_appは


def get_db():
    if 'db' not in g:
        # current_app.configのキーDATABASEで示されるファイルへのconnectionを確立する
        # ファイルはデータベース初期化時に作成される
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

# connectionが作成済みであるか調べる→存在する場合は閉じる
def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()
        
def init_db():
    db = get_db()
    
    # 指定されたファイルを開く
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

@click.command('init-db')
def init_db_command():
    """ clear the existing data and create new tables """
    init_db()
    click.echo('Initialised the database')

# Flaskアプリケーションを使ってinit/close_db関数をインスタンスに登録する
def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    