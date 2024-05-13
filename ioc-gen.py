def print_banner():
    blue_start = "\033[94m"
    color_reset = "\033[0m"
    print(blue_start + r"""

██╗ ██████╗  ██████╗     ██████╗ ███████╗███╗   ██╗
██║██╔═══██╗██╔════╝    ██╔════╝ ██╔════╝████╗  ██║
██║██║   ██║██║         ██║  ███╗█████╗  ██╔██╗ ██║
██║██║   ██║██║         ██║   ██║██╔══╝  ██║╚██╗██║
██║╚██████╔╝╚██████╗    ╚██████╔╝███████╗██║ ╚████║
╚═╝ ╚═════╝  ╚═════╝     ╚═════╝ ╚══════╝╚═╝  ╚═══╝
"""+ color_reset)
    print(blue_start + "IOC Generator Microsoft Defender for Endpoint by Alex L." + color_reset)

def process_file(file_path, data_type, output_file_path, details):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    with open(output_file_path, 'w') as outfile:
        header = "IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert"
        outfile.write(header + "\n")
        
        for line in lines:
            line = line.strip()
            if data_type == 'Url':
                prefix = details.get('prefix', '')
                if prefix:
                    line = f"{prefix}{line}"

            entry = f"{data_type},{line},,{details['action']},{details['severity']},{details['threat_name']},{details['description']},{details['response']},,,,{details['confirmed']}"
            outfile.write(entry + "\n")

def get_details(data_type):
    details = {
        'action': input("Enter the action to be taken \n Allow, Audit, Warn, BlockandRemediate(hashes), Block(Urls,Domains):\n> "),
        'severity': input("Enter the severity level \n Informational,Low,Medium,High:\n> "),
        'threat_name': input("Enter the threat name: "),
        'description': input("Enter the description: "),
        'response': input("Enter the recommended actions/response: "),
        'confirmed': input("Is alert generation confirmed? (TRUE/FALSE): ")
    }
    if data_type in ['Url', 'DomainName']:
        if data_type == 'Url':
            prefix_choice = input("Do you want to prepend 'http://' or 'https://' to URLs? (Enter http, https or none): ")
            if prefix_choice in ['http', 'https']:
                details['prefix'] = prefix_choice + "://"
            else:
                data_type = 'DomainName'

    return details, data_type

def main():
    print_banner()
    data_type = input("Enter the type of data to process (FileSha256, IpAddress, Url, or DomainName):\n> ")
    if data_type not in ['FileSha256', 'IpAddress', 'Url', 'DomainName']:
        print("Invalid data type entered.")
        return

    details, data_type = get_details(data_type)
    file_path = input("Enter the path to the file containing {}s:\n> ".format(data_type))
    output_file_path = input("Enter the path for the output file:\n> ")
    process_file(file_path, data_type, output_file_path, details)

if __name__ == "__main__":
    main()
