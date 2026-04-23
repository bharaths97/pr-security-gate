import subprocess


def archive_user_path(user_input):
    subprocess.run("tar -czf /tmp/archive.tgz " + user_input, shell=True)
