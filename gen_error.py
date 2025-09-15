#!/usr/bin/env python3

import configparser
import argparse
import os

def parse_ini(filepath):
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case for names
    config.read(filepath)
    return config

def generate_header(config, filename):
    out = []
    out.append(f"// Auto-generated from {os.path.basename(filename)}\n#pragma once\n")
    out.append("namespace my_errors {\n")

    # Generate nested namespaces for each section
    for section in config.sections():
        # Convert section name to valid C++ identifier
        namespace = section.upper().replace("ERROR", "").strip()
        out.append(f"namespace {namespace} {{  // {section} errors\n")
        
        for name, value in config[section].items():
            code, description = value.split(",", 1)
            out.append(f"constexpr int {name} = {code.strip()};  // {description.strip()}")
        
        out.append(f"}}  // namespace {namespace}\n")

    out.append("}  // namespace my_errors")
    return "\n".join(out)

def main():
    parser = argparse.ArgumentParser(
        description="Generate httpclient_error_codes.hpp from error_codes.ini"
    )
    parser.add_argument(
        "--input", "-i", 
        required=True, 
        help="Path to input .ini file"
    )
    parser.add_argument(
        "--output", "-o", 
        default="include/my_error_codes.hpp",
        help="Path to output .hpp file (default: include/my_error_codes.hpp)"
    )

    args = parser.parse_args()
    config = parse_ini(args.input)

    header_code = generate_header(config, args.input)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(header_code)

    print(f"✅ Generated: {args.output}")

if __name__ == "__main__":
    main()

# #!/usr/bin/env python3

# import configparser
# import argparse
# import os

# def parse_ini(filepath):
#     config = configparser.ConfigParser()
#     config.optionxform = str  # preserve case for names
#     config.read(filepath)
#     return config

# def generate_header(config, filename):
#     out = []
#     out.append(f"// Generated from {os.path.basename(filename)}\n#pragma once\n")
#     out.append("#include <string>\n#include <ostream>\n\nnamespace myerror {\n")

#     # Enums
#     for section in config.sections():
#         out.append(f"enum class {section} : int {{")
#         for name, value in config[section].items():
#             code, *_ = value.split(",", 1)
#             out.append(f"  {name} = {code.strip()},")
#         out.append("};\n")

#     # to_int helpers
#     for section in config.sections():
#         out.append(f"inline int to_int({section} e) {{ return static_cast<int>(e); }}")

#     out.append("}  // namespace error\n")
#     return "\n".join(out)

# def main():
#     parser = argparse.ArgumentParser(description="Generate error_codes.hpp from error_codes.ini")
#     parser.add_argument("--input", "-i", required=True, help="Path to input .ini file")
#     parser.add_argument("--output", "-o", required=True, help="Path to output .hpp file")

#     args = parser.parse_args()
#     config = parse_ini(args.input)

#     header_code = generate_header(config, args.input)

#     with open(args.output, "w") as f:
#         f.write(header_code)

#     print(f"✅ Generated: {args.output}")

# if __name__ == "__main__":
#     main()
