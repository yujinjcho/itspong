# Synopsis
Tool for connecting nearby ping pong players.

# Installation
Clone the repository.

`git clone https://github.com/yujinjcho/itspong.git`

Create a virtual environment. I'm using virtualenvwrapper in this case.

`mkvirtualenv itspong`

Install dependencies.

`pip install -r requirements.txt`

# Config
Create `config.py` and add to root project folder and fill in config variables below. Create new Google and Facebook projects to get IDs and SECRETs. Requires a database URI as well.

```
DEBUG=True
SECRET_KEY = 'SECRET'
GOOGLE_ID = 'GOOGLE_ID'
GOOGLE_SECRET = 'GOOGLE_SECRET'
FACEBOOK_APP_ID = 'FACEBOOK_APP_ID'
FACEBOOK_APP_SECRET = 'FACEBOOK_APP_SECRET'
SQLALCHEMY_DATABASE_URI = 'SQLALCHEMY_DATABASE_URI'
```

# Run Locally
Initialize database before running app.
```
python
>>>from app import db
>>>db.create_all()
>>>quit()

python run.py
```

# License
This project is licensed under the MIT License - see the [license.txt](https://github.com/yujinjcho/itspong/blob/master/license.txt) file for details