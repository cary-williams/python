'''
This script is used to deploy a site using elastic beanstalk.
It assumes that you already have the repo cloned.

Depends on GitPython

pip install GitPython

Follow the directions here to setup eb-cli
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3-install.html
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb3-init.html
'''

from subprocess import check_output, CalledProcessError
from os import chdir
from os.path import isfile, join
from git import Repo

# Set the path to your git repo, and the elastic beanstalk app name.
REPO_DIR = ""
EB_APP = ""

# Setting repo
REPO = Repo("%s" % (REPO_DIR))


def run(cmd, cwd=None):
    """
    Run a command and return stdout as text.
    """
    try:
        out = check_output(cmd, cwd=cwd, text=True)
        return out.strip()
    except TypeError:
        # For very old Python versions that don't support text=True
        out = check_output(cmd, cwd=cwd)
        return out.decode("utf-8", errors="replace").strip()
    except CalledProcessError as e:
        # Print whatever we can and exit
        msg = ""
        if getattr(e, "output", None):
            try:
                msg = e.output if isinstance(e.output, str) else e.output.decode("utf-8", errors="replace")
            except Exception:
                msg = ""
        print("Command failed: " + " ".join(cmd))
        if msg:
            print(msg)
        quit(1)


def chk_init():
    """
    Checks if beanstalk config exists.
    """
    print("Checking for config.yml ...")
    conf_file_exists = isfile(join(REPO_DIR, ".elasticbeanstalk", "config.yml"))
    if conf_file_exists:
        print("Config exists. Continuing ...")
        return True

    print("It looks like you're missing .elasticbeanstalk/config.yml from your repo directory.")
    while True:
        cont = INPUT("Do you want to continue? [yes/no] ").lower().strip()
        if cont == "yes":
            print("Continuing using " + REPO_DIR)
            return True
        if cont == "no":
            print("Exiting...")
            quit(0)
        print("Please type 'yes' or 'no'")


def env_check():
    """
    Prompts user for which environment to use.
    """
    while True:
        env = INPUT("What environment are you using? [nonprod/prod]: ").lower().strip()
        if env in ("nonprod", "prod"):
            if env == "nonprod":
                eb_env = EB_APP + "-develop"
                return env, eb_env
            eb_env = EB_APP + "-prod"
            return env, eb_env
        print("You must select either 'nonprod' or 'prod'.")


def repo_check():
    """
    Checks the current git branch and changes directory to repo.
    """
    branch = REPO.active_branch.name

    print("Changing directory to " + REPO_DIR + " ...")
    chdir(REPO_DIR)

    if branch in ("master", "main", "develop"):
        return branch

    print(
        "You have selected the branch " + branch + ". Verify this "
        "is the correct branch before confirming the deployment."
    )
    return branch


def pull_code(branch):
    """
    Pulls the latest code and verifies the current branch is correct.
    """
    print(run(["git", "checkout", branch], cwd=REPO_DIR))
    print(run(["git", "pull"], cwd=REPO_DIR))

    # Check if the checkout worked properly
    current_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO_DIR)
    if current_branch != branch:
        print(
            "Sorry. The branch " + branch + " was not checked out successfully. Please try again ..."
        )
        quit(1)

    # Show last commit
    latest = run(["git", "log", "-n", "1", "--oneline"], cwd=REPO_DIR)
    print("\n\nLatest: " + latest)
    return current_branch


def prod_protection(eb_env, branch):
    """
    Exits the script if trying to deploy to prod without being on master or main.
    """
    if eb_env == EB_APP + "-prod" and branch not in ("master", "main"):
        print("#################################################")
        print("PROD PROTECTION ALERT")
        print("prod updates must be from the master or main branch only. Exiting ...")
        print("#################################################")
        quit(1)


def deploy(env, current_branch, eb_env):
    """
    Deploys the code.
    """
    deploy_env = env
    deploy_app = eb_env
    deploy_branch = current_branch

    print("You are deploying to " + deploy_env + " using the " + deploy_branch + " branch.")

    while True:
        confirmation = INPUT("Do you want to continue? [yes/no] ").lower().strip()
        if confirmation == "yes":
            print("Setting up beanstalk")
            print(run(["eb", "use", deploy_app], cwd=REPO_DIR))
            print("Deploying...")
            print(run(["eb", "deploy"], cwd=REPO_DIR))
            quit(0)
        if confirmation == "no":
            print("Exiting. Goodbye.")
            quit(0)
        print("Please type yes or no to continue.")


if __name__ == "__main__":
    INPUT = input
    chk_init()
    env, eb_env = env_check()
    branch = repo_check()
    prod_protection(eb_env, branch)
    current_branch = pull_code(branch)
    deploy(env, current_branch, eb_env)
