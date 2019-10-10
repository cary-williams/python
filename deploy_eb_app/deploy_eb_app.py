'''
This script is used to deploy a site using elastic beanstalk.
It assumes that you already have the repo cloned.

Depends on GitPython

pip install GitPython

Follow the directions here to setup eb-cli
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3-install.html
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb3-init.html
'''

from __future__ import print_function
from sys import version_info
from subprocess import check_output
from os import chdir
from os.path import isfile
from git import Repo

# Set the path to your git repo, and the elastic beanstalk app name.
REPO_DIR = ""
EB_APP = ""

# Setting repo and branch
REPO = Repo('%s' % (REPO_DIR))

def chk_init():
    '''
        Checks if beanstalk config exists
    '''

    print("Checking for config.yml ...")
    conf_file_exists = isfile(REPO_DIR + "/.elasticbeanstalk/config.yml")
    if conf_file_exists:
        print("Config exists. Continuing ...")
        return conf_file_exists
    if not conf_file_exists:
        print("It looks like you're missing elasticbeanstalk/config.yml "
              "from your repo directory.")
        while True:
            cont = INPUT("Do you want to continue? [yes/no] ").lower()
            if cont == "yes":
                print("Continuing using " + REPO_DIR)
                return cont
            if cont == "no":
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
        env = INPUT("What environment are you using? [nonprod/prod]: ").lower()
        if env in ('nonprod', 'prod'):
            if env =="nonprod":
                eb_env = EB_APP + "-develop"
                return env, eb_env
            if env == "prod":
                eb_env = EB_APP + "-prod"
                return env, eb_env
        print("You must select either 'qa' or 'prod'.")
        continue


def repo_check():
    '''
        Checks the current git branch
    '''

    branch = REPO.active_branch
    print("Changing directory to " + REPO_DIR + " ...")
    chdir(REPO_DIR)
    while True:
        if branch in ('master', 'develop'):
            return branch
        if branch not in ('master', 'develop'):
            print("You have selected the branch " + branch + ". Verify this "
                  "is the correct branch before confirming the deployment.")
            break
    return branch


def pull_code(branch):
    '''
        pulls the latest code and verifies the current branch is correct
    '''

    print(check_output(['git', 'checkout', branch]))
    print(check_output(['git', 'pull']))
    # Check if the checkout worked properly
    current_branch = check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    if current_branch.strip() != branch:
        print("Sorry. The branch " + branch + " was not"
              "checked out successfully. Please try again ...")
        quit()
    else:
        # show last commit
        print("\n\nLatest" + check_output(['git', 'log', '-n', '1']))
    return current_branch


def prod_production(eb_env, branch):
    '''
        Exits the script if trying to deploy to prod without master branch
    '''

    if eb_env == EB_APP + "-prod" and branch != "master":
        print("#################################################")
        print("PROD PROTECTION ALERT")
        print("prod updates must be from the master branch only."
              " Exiting ...")
        print("#################################################")
        quit()


def deploy(env, current_branch, eb_env):
    '''
        Deploys the code
    '''
    deploy_env = env
    deploy_app = eb_env
    deploy_branch = current_branch
    print("You are deploying to IZCOM " + deploy_env +
          " using the " + deploy_branch + " branch.")

    while True:
        confirmation = INPUT("Do you want to continue?. [yes/no]").lower()
        # Make sure the response is valid
        if confirmation == "yes":
            print("Setting up beanstalk")
            print(check_output(['eb', 'use', deploy_app]))
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
    env, eb_env = env_check()
    branch = repo_check()
    prod_production(eb_env, branch)
    current_branch = pull_code(branch)
    deploy(env, current_branch, eb_env)
