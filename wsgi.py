from main import app
import main
import os
 
if __name__ == "__main__":
    main.create_tables(main.connect_db())
    app.secret_key = os.urandom(24)
    app.run()
