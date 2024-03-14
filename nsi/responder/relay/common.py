import re

# Start Fortra vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Utility and helper functions for the example scripts
#
# Author:
#   Martin Gallo (@martingalloar)
#
# Regular expression to parse target information
target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")


# Regular expression to parse credentials information
credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")


def parse_target(target):
    """ Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    domain, username, password, remote_name = target_regex.match(target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


def parse_credentials(credentials):
    """ Helper function to parse credentials information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>

    :param credentials: credentials to parse
    :type credentials: string

    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    domain, username, password = credential_regex.match(credentials).groups('')

    return domain, username, password

def parse_listening_ports(value):
    ports = set()
    for entry in value.split(","):
        items = entry.split("-")
        if len(items) > 2:
            raise ValueError
        if len(items) == 1:
            ports.add(int(items[0])) # Can raise ValueError if casted value not an Int, will be caught by calling method
            continue
        item1, item2 = map(int, items) # Can raise ValueError if casted values not an Int, will be caught by calling method
        if item2 < item1:
            raise ValueError("Upper bound in port range smaller than lower bound")
        ports.update(range(item1, item2 + 1))

    return ports

# End Fortra ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^