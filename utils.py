from pathlib import Path


def get_exploits() -> list:
    """Read all .rs exploits from the current directory and its subdirectories."""
    example_exploits = []
    filenames = []

    for filepath in Path.cwd().rglob("*.rs"):
        filenames.append(str(filepath))
        with open(filepath, "r") as file:
            contents = file.readlines()
            contents = "".join(contents)
            example_exploits.append(contents)

    # print("We have {} example exploits.".format(len(example_exploits)))

    return filenames, example_exploits


def extract_class(response):
    """Extract the class of an exploit from the response of an LLM.
    If no number found, return 0 (no exploit)."""
    reversed_s = response[::-1]

    for char in reversed_s:
        if char.isdigit():
            return int(char)

    return 0


def map_class_with_output(class_number):
    """Map a class number to a JSON object with title and description keys."""

    vulnerability_map = {
        0: {
            "title": "No vulnerability found.",
            "description": "The code does not contain any vulnerabilities.",
            "severity": "INFO",
            "error_code": "0x0",
        },
        1: {
            "title": "Integer overflow.",
            "description": "An arithmetic operation resulted in a value that exceeds the maximum representable value for the data type.",
            "severity": "MEDIUM",
            "error_code": "411x",
        },
        2: {
            "title": "Integer underflow.",
            "description": "An arithmetic operation resulted in a value that is less than the minimum representable value for the data type.",
            "severity": "MEDIUM",
            "error_code": "44x",
        },
        3: {
            "title": "Unsafe memory.",
            "description": "Accessing memory in an unsafe manner, potentially leading to security vulnerabilities.",
            "severity": "MEDIUM",
            "error_code": "32x",
        },
        4: {
            "title": "Incorrect execution of authorization.",
            "description": "Failure to properly check authorization before executing a privileged operation.",
            "severity": "MEDIUM",
            "error_code": "01x",
        },
        5: {
            "title": "Depth of cross-contract call over four.",
            "description": "The depth of a cross-contract call exceeds the allowed limit.",
            "severity": "HIGH",
            "error_code": "33x",
        },
        6: {
            "title": "Reentrancy attack.",
            "description": "A contract's reentrancy vulnerability allows it to be called repeatedly before previous invocations complete.",
            "severity": "HIGH",
            "error_code": "14x",
        },
        7: {
            "title": "Errors in logic and arithmetic.",
            "description": "Logical or arithmetic errors in the code that can lead to unexpected behavior.",
            "severity": "HIGH",
            "error_code": "52x",
        },
        8: {
            "title": "Computational units limit.",
            "description": "The computation exceeds the computational units limit imposed by the platform.",
            "severity": "LOW",
            "error_code": "33x",
        },
    }

    return vulnerability_map.get(
        class_number,
        {
            "title": "Unknown vulnerability.",
            "description": "The vulnerability class number provided does not match any known vulnerabilities.",
        },
    )
