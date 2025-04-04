#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: ipaddress.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:08:10
# Modified: 2025-03-23 16:11:02

import ipaddress

def validate_ip_address(ip: str) -> dict:
    """
    Validates and classifies an IP address using the standard library.

    Args:
        ip (str): The IP address to validate.

    Returns:
        dict: {
            "IP Address": str,
            "Valid": bool,
            "Type": "IPv4" | "IPv6" | "Invalid",
            "Private": bool,
            "Loopback": bool,
            "Multicast": bool,
            "Reserved": bool,
            "Global": bool
        }
    """
    result = {
        "IP Address": ip,
        "Valid": False,
        "Type": "Invalid",
        "Private": False,
        "Loopback": False,
        "Multicast": False,
        "Reserved": False,
        "Global": False
    }

    try:
        ip_obj = ipaddress.ip_address(ip)
        result["Valid"] = True
        result["Type"] = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
        result["Private"] = ip_obj.is_private
        result["Loopback"] = ip_obj.is_loopback
        result["Multicast"] = ip_obj.is_multicast
        result["Reserved"] = ip_obj.is_reserved
        result["Global"] = ip_obj.is_global
    except ValueError:
        pass

    return result


if __name__ == "__main__":
    test_ips = [
        "192.168.1.1",         # Private IPv4
        "8.8.8.8",             # Public IPv4
        "0.0.0.0",             # Reserved IPv4
        "255.255.255.255",     # Broadcast
        "127.0.0.1",           # Loopback IPv4
        "::1",                 # Loopback IPv6
        "2001:db8::",          # Reserved IPv6
        "ff02::1",             # Multicast IPv6
        "not.an.ip"            # Invalid input
    ]

    print("IP Address Validation Test Results:\n")
    for ip in test_ips:
        result = validate_ip_address(ip)
        status = "✅" if result["Valid"] else "❌"
        summary = f"{result['Type']:5}  |  Private: {result['Private']}  Loopback: {result['Loopback']}"
        print(f"{status} {ip:20} → {summary}")

