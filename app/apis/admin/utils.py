import subprocess


def get_disk_usage(parameters: str):
    allowed_params = ["-a"]
    input_param = parameters.strip()
    for param in input_param:
        if param not in allowed_params:
            return "Invalid parameter detected"
    command = ["df" ,  "-h "]
    command.extend(input_param)

    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        usage = result.stdout.strip().decode()
    except:
        raise Exception("An unexpected error was observed")
    return usage