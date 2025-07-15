import re

def parse_logs(filename):
    suspicious = []
    pattern = re.compile(r"(failed login|error|unauthorized access)", re.IGNORECASE)

    try:
        with open(filename, "r") as log:
            for line in log:
                if pattern.search(line):
                    suspicious.append(line)

        with open("flagged_output.txt", "w") as output:
            output.writelines(suspicious)

        print(f"{len(suspicious)} suspicious entries found and saved to flagged_output.txt.")

    except FileNotFoundError:
        print("Log file not found. Make sure 'system_log.txt' is in the same folder.")

if __name__ == "__main__":
    parse_logs("system_log.txt")
