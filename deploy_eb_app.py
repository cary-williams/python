'''
This script is used to deploy a site using elastic beanstalk.
It assumes that you already have the repo cloned.

Follow the directions here to setup eb-cli
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3-install.html
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb3-init.html
'''

from __future__ import print_function
from sys import version_info
from subprocess import check_output
from os import chdir
from os.path import isfile

# Set the path to your git repo, and the elastic beanstalk app name.
REPO_DIR = ""
EB_APP = ""


def chk_init():
    '''
        Checks if beanstalk config exists
    '''

    print("Checking for config.yml ...")
    conf_file_exists = isfile(REPO_DIR + "/.elasticbeanstalk/config.yml")
    if conf_file_exists:
        print("Config exists. Continuing ...")
        return conf_file_exists
    else:
        print("It looks like you're missing elasticbeanstalk/config.yml "
              "from your repo directory.")
        while True:
            cont = INPUT("Do you want to continue? [yes/no] ").lower()
            if cont == "yes":
                print("Continuing using " + REPO_DIR)
                return cont
            elif cont == "no":
                print("Exiting...")
                quit()
            else:
                print("Please type 'yes' or 'no'")
                continue


def env_check():
    '''
        Prompts user for which environment to use
    '''

    while True:
        ENV = INPUT("What environment are you using? [nonprod/prod]: ").lower()
        if ENV == "nonprod":
            EB_ENV = EB_APP + "-develop"
            return ENV, EB_ENV
        elif ENV == "prod":
            EB_ENV = EB_APP + "-prod"
            return ENV, EB_ENV
        else:
            print("You must select either 'qa' or 'prod'.")
            continue


def repo_check():
    '''
        Prompts user for branch of the repo to use
    '''

    print("Changing directory to " + REPO_DIR + " ...")
    chdir(REPO_DIR)
    while True:
        BRANCH = INPUT("What branch are you using? [develop/master]: ").lower()
        if BRANCH == "master" or BRANCH == "develop":
            return BRANCH
        if BRANCH == "" or BRANCH == " ":
            print("You must enter a branch.")
        else:
            print("You have selected the branch " + BRANCH + ". Verify this "
                  "is the correct branch before confirming the deployment.")
            break
    return BRANCH


def pull_code(BRANCH):
    '''
        pulls the latest code and verifies the current branch is correct
    '''

    print(check_output(['git', 'checkout', BRANCH]))
    print(check_output(['git', 'pull']))
    # Check if the checkout worked properly
    CURRENT_BRANCH = check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    if CURRENT_BRANCH.strip() != BRANCH:
        print("Sorry. The BRANCH " + BRANCH + " was not"
              "checked out successfully. Please try again ...")
        quit()
    else:
        # show last commit
        print("\n\nLatest" + check_output(['git', 'log', '-n', '1']))
    return CURRENT_BRANCH


def prod_production(EB_ENV, BRANCH):
    '''
        Exits the script if trying to deploy to prod without master BRANCH
    '''

    if EB_ENV == EB_APP + "-prod" and BRANCH != "master":
        print("#################################################")
        print("PROD PROTECTION ALERT")
        print("prod updates must be from the master branch only."
              " Exiting ...")
        print("#################################################")
        quit()


def deploy(ENV, CURRENT_BRANCH, EB_ENV):
    '''
        Deploys the code
    '''
    DEPLOY_ENV = ENV
    DEPLOY_APP = EB_ENV
    deploy_branch = CURRENT_BRANCH
    print("You are deploying to IZCOM " + DEPLOY_ENV +
          " using the " + deploy_branch + " BRANCH.")

    while True:
        confirmation = INPUT("Do you want to continue?. [yes/no]").lower()
        # Make sure the response is valid
        if confirmation == "yes":
            print("Setting up beanstalk")
            print(check_output(['eb', 'use', DEPLOY_APP]))
            print("Deploying...")
            print(check_output(['eb', 'deploy']))
            quit()
        elif confirmation == "no":
            print("Exiting. Goodbye.")
            quit()
        else:
            print("Please type yes or no to continue.")
            continue


if __name__ == "__main__":
    INPUT = input
    if version_info[:2] <= (2, 7):
        INPUT = raw_input
    chk_init()
    ENV, EB_ENV = env_check()
    BRANCH = repo_check()
    prod_production(EB_ENV, BRANCH)
    CURRENT_BRANCH = pull_code(BRANCH)
    deploy(ENV, CURRENT_BRANCH, EB_ENV)
