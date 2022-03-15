CPE = "cpe:/o:arubanetworks:arubaos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105733" );
	script_cve_id( "CVE-2016-0801", "CVE-2016-0802", "CVE-2015-8605" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12338 $" );
	script_name( "ArubaOS Multiple Vulnerabilities (ARUBA-PSA-2016-007)" );
	script_xref( name: "URL", value: "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2016-007.txt" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to one of the following software versions:

  - - ArubaOS 6.3.1.21 or later

  - - ArubaOS 6.4.2.16 or later

  - - ArubaOS 6.4.3.7 or later

  - - ArubaOS 6.4.4.5 or later" );
	script_tag( name: "summary", value: "ArubaOS is prone to multiple vulnerabilities

A buffer over-read vulnerability allows an unauthenticated user to read from uninitialized
memory locations.  Based on analysis of the flaw, Aruba does not believe that this
memory is likely to contain sensitive information.

The Broadcom Wi-Fi driver used in the AP-2xx series access points allows attackers
to execute arbitrary code or cause a denial of service (memory corruption) via crafted wireless
control message packets.  The attacker must be joined to the network (wired or wireless) - this
vulnerability may not be exercised by an unauthenticated user against a WPA2 network.

A flaw in the ISC DHCP server allows remote attackers to cause a denial of service (application crash)
via an invalid length field in a UDP IPv4 packet.  The flawed DHCP server is incorporated into ArubaOS.
If the DHCP server is enabled in an Aruba mobility controller, an attacker could cause it to crash.
ArubaOS would automatically restart the process.  However, DHCP services would be disrupted temporarily." );
	script_tag( name: "affected", value: "-- ArubaOS 6.3 prior to 6.3.1.21

  - - ArubaOS 6.4.2.x prior to 6.4.2.16

  - - ArubaOS 6.4.3.x prior to 6.4.3.7

  - - ArubaOS 6.4.4.x prior to 6.4.4.5" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-26 15:30:28 +0200 (Thu, 26 May 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_arubaos_detect.sc" );
	script_mandatory_keys( "ArubaOS/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.3", test_version2: "6.3.1.20" )){
	fix = "6.3.1.21";
}
if(version_in_range( version: version, test_version: "6.4.2", test_version2: "6.4.2.15" )){
	fix = "6.4.2.16";
}
if(version_in_range( version: version, test_version: "6.4.3", test_version2: "6.4.3.6" )){
	fix = "6.4.3.7";
}
if(version_in_range( version: version, test_version: "6.4.4", test_version2: "6.4.4.4" )){
	fix = "6.4.4.5";
}
if(fix){
	model = get_kb_item( "ArubaOS/model" );
	report = "Installed Version: " + version + "\n" + "Fixed Version:     " + fix + "\n";
	if(model){
		report += "Model:             " + model + "\n";
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

