from stem.control import Controller
import stem.process
import os
import shutil
import sys
import subprocess
import logging


def run_hidden_service(socks_port=None, control_port="", application=None, flask_port=None, verbose=True, leave_address_alive=False, torrc_file=False, tor_password=None, hidden_dir_name=None, show_requests=True):
    
    if show_requests == False:
        log = logging.getLogger('werkzeug')
        log.disabled = True

    def bootstrapped(line):
        if "Bootstrapped" in line:
            print(line)

    def hash_passwd(password):
        x = subprocess.check_output(['tor', "--quiet", '--hash-password', password])
        y = str(x.decode("utf-8"))
        return y
    try:
        if int(os.getuid()) == 0:
            if verbose == True:
                print("Hidden Services should not be launched as a superuser or root, aborting")
            sys.exit(1)

        if application == None:
            if verbose == True:
                print("No Flask App found!")
            sys.exit(1)

        if control_port == "":
            if verbose == True:
                print("No Control Port was set")
            sys.exit(1)

        #Checking Port Layout
        if not socks_port == None:
            socks_port = int(socks_port)

        elif socks_port == None:
            socks_port = int(control_port) + 1

        if not flask_port == None:
            flask_port = int(flask_port)

        elif flask_port == None:
            flask_port = int(control_port) + 2

        if int(control_port) == int(socks_port):
            if verbose == True:
                print("The Control Port and the Socks Port are on the same Port")
            sys.exit(1)

        if int(control_port) == int(flask_port):
            if verbose == True:
                print("The Control Port and the Flask Port are on the same Port")
            sys.exit(1)

        if int(socks_port) == int(flask_port):
            if verbose == True:
                print("The Socks Port and the Flask Port are on the same Port")
            sys.exit(1)
    except Exception as ex:
        if verbose == True:
            print("Error in Port Configuration :", ex)
        sys.exit(1)

    #Checking Other Config
    try:
        if not hidden_dir_name == None:
            hidden_dir_name = "FHS:" + str(hidden_dir_name)
        else:
            hidden_dir_name = "FHS:" + str(control_port)

        if not tor_password == None:
            tor_password = str(tor_password)
        else:
            tor_password = str(hidden_dir_name) + str(flask_port)

        hashed_password = hash_passwd(tor_password)
    except Exception as ex:
        if verbose == True:
            print("Error in Name & Password Configuration :", ex)
        sys.exit(1)

    #Starting Tor
    try:
        if torrc_file == True:
            c_port = str(control_port)
            s_port = str(socks_port)
            with open("torrc", "w") as f:
                f.write("SOCKSPort " + s_port + "\nControlPort " + c_port + "\nCookieAuthentication 1\nRunAsDaemon 0\nHashedControlPassword " + hashed_password)
            if verbose == True:
                tor_process = stem.process.launch_tor(torrc_path="torrc", init_msg_handler = bootstrapped)
                print("")
            else:
                tor_process = stem.process.launch_tor(torrc_path="torrc")
        elif torrc_file == False:
            c_port = str(control_port)
            s_port = str(socks_port)
            torrc_config = {"SOCKSPort": s_port, "ControlPort": c_port, "CookieAuthentication": "1", "RunAsDaemon": "0", "HashedControlPassword": hashed_password}
            if verbose == True:
                tor_process = stem.process.launch_tor_with_config(config = torrc_config, init_msg_handler = bootstrapped)
                print("")
            else:
                tor_process = stem.process.launch_tor_with_config(config = torrc_config)
        else:
            if verbose == True:
                print("Unknown input in the 'torrc_file' option ( Should be 'True' or 'False' )")
            sys.exit(1)
    except Exception as ex:
        if verbose == True:
            print("Error in Torrc Configuration & Tor Process Spawning :", ex)
        sys.exit(1)

    #Starting the Hidden Service
    try:
        with Controller.from_port(port = control_port) as controller:
            controller.authenticate(password=tor_password)
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
                sys.exit(1)

            try:
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
            print("Error in Hidden Service Spawning :", ex)
        tor_process.kill()
        try:
            shutil.rmtree(hidden_service_dir)
        except:
            pass
