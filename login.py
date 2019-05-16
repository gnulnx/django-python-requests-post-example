"""
Simple demostration of how to use the Python Requests library to make a post request using the django csrf token.
In this example we login to a django admin site.  It should be easy enough to extrapolate from this example to other
forms that require POST and csrf tokens.

To use this first start your django website... or have one already running.

"""

import requests
import json
from getpass import getpass


def login(username, password=None, url='http://127.0.0.1:8000/admin/login/?next=/admin/'):
    with requests.Session() as session:
        if not password:
            password = getpass()

        # Make initial get request and retreive csrftoken from cookies
        resp = session.get(url)
        csrf_token = resp.cookies.get('csrftoken')

        # Now make post request with username/password to login
        # Both the csrftoken key in cookies AND the X-CSRFToken key in headers are required
        resp = requests.post(
            url,
            data={'username': username, 'password': password},
            cookies={'csrftoken': csrf_token},
            headers={'X-CSRFToken': csrf_token}
        )

        # Perform a couple of checks to ensure that we are in fact logged in
        if resp.status_code != 200:
            raise Exception("Response failed with %s" % resp)
        elif '''<input type="text" name="username" autofocus required id="id_username">''' in resp.content.decode('utf-8'):
            # Response was 200, but there were errors on the form.
            raise Exception("Invalid Login")

        # Login successful so return the resp
        return resp


if __name__ == '__main__':
    # TODO Change to match the username/password login credentials for your site.
    resp = login('admin', 'menu')

    if resp.status_code == 200:
        print("Login successful")
        print(resp.content.decode('utf-8'))














