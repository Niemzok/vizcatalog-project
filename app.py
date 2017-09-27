import random
import string
import json
import httplib2
import requests
from functools import wraps

from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import session as login_session, flash, make_response
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, User, Viz
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError


app = Flask(__name__)


# Load Client Secret for Google Authentication
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Data Viz Gallery"

# Connect to Database and create database session
engine = create_engine('sqlite:///vizzes.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# JSON APIs to view all vizzes of the category
@app.route('/category/<int:category_id>/JSON')
def categoryVizzesJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    vizzes = session.query(Viz).filter_by(category_id=category.id).all()
    return jsonify(Vizzes=[v.serialize for v in vizzes])


# JSON APIs to view all categorie
@app.route('/category/JSON')
def categoryJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange'
    url += ('_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token='
    url += '%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'\
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Setup Google Authentication
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        print "0"
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        print "1"
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        print "3"
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        print "4"
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                 'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output
# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
#Decorator to check whether a user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    print login_session['provider']
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            del login_session['access_token']
            del login_session['gplus_id']
            #gdisconnect()
        if login_session['provider'] == 'facebook':
            #fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLogin'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showLogin'))


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase+string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, session=login_session)


@app.route('/')
@login_required
def showHome():
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('categories.html', categories=categories)


@app.route('/category/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               description=request.form['description'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('newcategory.html')



# Edit a Category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    categoryToEdit = session.query(Category).filter_by(id=category_id).one()
    #make sure logged in user is the owner of the category
    if login_session['user_id'] != categoryToEdit.user_id:
        flash('You are not the owner of Category %s.' % categoryToEdit.name)
        return redirect(url_for('showCategory',category_id=category_id  ))
    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
        if request.form['description']:
            categoryToEdit.description = request.form['description']
        session.add(categoryToEdit)
        flash('Viz %s Successfully Created' % categoryToEdit.name)
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('editcategory.html',
                               category=categoryToEdit)


# Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    #make sure logged in user is the owner of the category
    if login_session['user_id'] != categoryToDelete.user_id:
        flash('You are not the owner of Category %s.' % categoryToDelete.name)
        return redirect(url_for('showCategory', category_id=category_id))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('deletecategory.html',
                               category=categoryToDelete)


# show a specific category page
@app.route('/category/<int:category_id>/', methods=['GET', 'POST'])
@login_required
def showCategory(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    vizzes = session.query(Viz).filter_by(category_id=category_id).all()
    return render_template('category.html',
                           category=category, vizzes=vizzes)


@app.route('/category/<int:category_id>/viz/new', methods=['GET', 'POST'])
@login_required
def newViz(category_id):
    if request.method == 'POST':
        newViz = Viz(name=request.form['name'],
                     description=request.form['description'],
                     link=request.form['link'],
                     author_name=request.form['author_name'],
                     height='1000px',
                     width='100%',
                     user_id=login_session['user_id'],
                     category_id=category_id)
        session.add(newViz)
        flash('New Viz %s Successfully Created' % newViz.name)
        print 'new Viz is here'
        session.commit()
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('newviz.html')


@app.route('/category/<int:category_id>/viz/<int:viz_id>',
           methods=['GET', 'POST'])
@login_required
def showViz(category_id, viz_id):
    viz = session.query(Viz).filter_by(id=viz_id).one()
    return render_template('viz.html', viz=viz, category_id=category_id)


# Edit a Viz
@app.route('/category/<int:category_id>/viz/<int:viz_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editViz(category_id, viz_id):
    vizToEdit = session.query(Viz).filter_by(id=viz_id).one()
    #make sure logged in user is the owner of the viz
    if  login_session['user_id'] != vizToEdit.user_id:
        flash('You are not the owner of Viz %s.' % vizToEdit.name)
        return redirect(url_for('showViz', category_id=category_id,
                       viz_id=viz_id))
    if request.method == 'POST':
        if request.form['name']:
            vizToEdit.name = request.form['name']
        if request.form['description']:
            vizToEdit.description = request.form['description']
        if request.form['link']:
            vizToEdit.link = request.form['link']
        if request.form['author_name']:
            vizToEdit.author_name = request.form['author_name']
        if request.form['height']:
            vizToEdit.height = request.form['height']
        if request.form['width']:
            vizToEdit.width = request.form['width']
        session.add(vizToEdit)
        flash('Viz %s Successfully Created' % vizToEdit.name)
        session.commit()
        return redirect(url_for('showViz', category_id=category_id,
                                viz_id=vizToEdit.id))
    else:
        return render_template('editviz.html', viz=vizToEdit,
                               category_id=category_id)


# Delete a Viz
@app.route('/category/<int:category_id>/viz/<int:viz_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteViz(category_id, viz_id):
    vizToDelete = session.query(Viz).filter_by(id=viz_id).one()
    #make sure logged in user is the owner of the viz
    if  login_session['user_id'] != vizToDelete.user_id:
        flash('You are not the owner of Viz %s.' % vizToDelete.name)
        return redirect(url_for('showViz', category_id=category_id,
                       viz_id=viz_id))
    if request.method == 'POST':
        session.delete(vizToDelete)
        flash('%s Successfully Deleted' % vizToDelete.name)
        session.commit()
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('deleteviz.html', viz=vizToDelete,
                               category_id=category_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
