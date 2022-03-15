CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106657" );
	script_cve_id( "CVE-2017-3878" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_name( "Cisco Nexus 9000 Series Switches Telnet Login Denial of Service Vulnerability " );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-nss" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "A vulnerability in the Telnet remote login functionality of Cisco NX-OS
Software running on Cisco Nexus 9000 Series Switches could allow an unauthenticated, remote attacker to cause a
Telnet process used for login to terminate unexpectedly and the login attempt to fail. There is no impact to
user traffic flowing through the device." );
	script_tag( name: "insight", value: "The vulnerability is due to incomplete input validation of Telnet packet
headers. An attacker could exploit this vulnerability by sending a crafted Telnet packet to an affected system
during a remote Telnet login attempt." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to cause the Telnet process on
the affected system to restart unexpectedly, resulting in a denial of service (DoS) condition for the Telnet
process." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-16 11:30:46 +0700 (Thu, 16 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( nx_model, "^N9K" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version == "7.0(3)I3(0.170)"){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

