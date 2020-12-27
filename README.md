# Flask-Hidden-Service :
Flask-Hidden-Service is a small project that tries to make creating Hidden Services using Flask easier, it uses **Stem** , a Python controller library for [Tor](https://www.torproject.org/) .
In this script, **Stem** routes the flask application's page over tor to create a so called **"Tor Hidden Service"**, these services can only be reached with the [Tor Browser](https://tb-manual.torproject.org/) or any requesting tool using a tor proxy.

# ⚠️ Important ⚠️ :
This script is still experimental and i cannot give any promise that it will work 100% fine, so ***do not rely on it not to leak***.
# Feature :
This script takes the desired **Tor Control Port** and generates a  custom **torrc** file, which contains the following :
* Control Port
* Cookie Authentication
* Run Type ( Daemon )
* Hashed Control Password ( will be auto generated )

To keep the flask-hidden-service-apps clean, you can import the script by importing the `hidden_service.py` file.
This can be done by adding the following line in the import section of your program : `from hidden_service import run_hidden_service` .

# Requirements :

* To Install the requirements for the script, execute: `pip install -r requirements.txt`



# Usage  & Example :
**Most Important Detail :**  ⚠️ ***DO NOT RUN THIS SCRIPT AS ROOT OR WITH SUDO*** ⚠️

In a normal **flask-app** you start the website by adding `app.run()` to the end of the program.
Instead of doing that, you use the function provided by **hidden_services** called **run_hidden_service** and give it the
**Required data** :
* ***control_port*** = [PORT_YOU_CHOSE]
* ***application*** = [THE_VAR_OF_YOUR_APP] ( example :  **app**   from the code `app = Flask(__name__)` )

**Optional Data** :
* ***verbose*** = `True`  or `False` ( this will turn the print functions of the script **on** or **off** )
* ***leave_address_alive*** = `True` or `False` (if this is option is `True` the **onion address** will be saved and reused if the same **control port** gets selected again )
* ***flask_port*** = [CUSTOM_FLASK_PORT] ( ⚠️ Don't use this, **experimental** ⚠️)
* ***app_data*** = [CUSTOM_FLASK_APP.RUN_DATA] ( ⚠️ Don't use this, **experimental** ⚠️)

## This is an example usage of the **run_hidden_service** function provided by my script.

![alt text](https://github.com/Blessed-NullArray/Flask-Hidden-Service/blob/master/imgs/example.png?raw=true)
