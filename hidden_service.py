from stem.control import Controller
import stem.process
import os
import shutil
import sys
import subprocess


def run_hidden_service(control_port=10001, application=None, flask_port=None, verbose=True, app_data=None, leave_address_alive=False):
    if application == None:
        if verbose == True:
            print("No Flask App found!")
        sys.exit(0)

    def hash_passwd(password):
        s = subprocess.check_output(['tor', '--hash-password', password])
        s_ex = s.decode("utf-8")
        return s_ex

    hidden_dir_name = str(control_port)
    if flask_port == None:
        if app_data == None:
            flask_port = str(control_port + 1)
    passwd = hidden_dir_name + flask_port
    hashed_pass = hash_passwd(passwd)

    c_p = str(control_port)
    with open("torrc", "w") as f:
        f.write("ControlPort " + c_p + "\nCookieAuthentication 1\nRunAsDaemon 0\nHashedControlPassword " + str(hashed_pass))

    tor_process = stem.process.launch_tor(torrc_path="torrc")
    try:
        with Controller.from_port(port = control_port) as controller:
            controller.authenticate(password=passwd)
            #Setup Hidden Service
            hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', '/tmp'), str(hidden_dir_name))
            if verbose == True:
                print("Setting up the hidden service in " + str(hidden_service_dir))
            #Send Flask Request to Hidden Service
            result = controller.create_hidden_service(hidden_service_dir, 80, target_port = flask_port)
            if result.hostname:
                if verbose == True:
                    print("Spawning Hidden Service at : " + str(result.hostname))
            else:
                if verbose == True:
                    print("Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")
                sys.exit(0)

            try:
                if not app_data == None:
                    application.run(app_data)

                application.run(port=flask_port)
            finally:
                if verbose == True:
                    print("Shutting down the Hidden Service")
                if leave_address_alive == False:
                    controller.remove_hidden_service(hidden_service_dir)
                    shutil.rmtree(hidden_service_dir)
                if verbose == True:
                    print("Despawning Done")
                tor_process.kill()
    except Exception as ex:
        if verbose == True:
            print("Error : ", ex)
        tor_process.kill()
        shutil.rmtree(hidden_service_dir)
