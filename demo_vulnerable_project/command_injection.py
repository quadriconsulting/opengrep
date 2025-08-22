
import os
import subprocess

def backup_file(filename):
    # VULNERABLE: Command injection via os.system
    os.system(f"cp {filename} /backup/")

def process_upload(user_filename):
    # VULNERABLE: Command injection via subprocess with shell=True
    subprocess.run(f"file {user_filename}", shell=True)
    
def convert_image(image_path):
    # VULNERABLE: Command injection in subprocess
    cmd = "convert " + image_path + " output.jpg"
    os.system(cmd)
