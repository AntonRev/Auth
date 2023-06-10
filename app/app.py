import uvicorn
from flask_migrate import Migrate

import application
from db.db import db

app = application.create_app()
migrate = Migrate(app, db)


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)
