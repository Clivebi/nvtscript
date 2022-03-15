CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105984" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-13 12:50:32 +0700 (Fri, 13 Mar 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-3391" );
	script_bugtraq_id( 70300 );
	script_name( "Cisco ASA Local Path Inclusion Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "Cisco ASA is prone to a local path inclusion vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the function that exports environment variables
of Cisco ASA Software could allow an authenticated, local attacker to inject a malicious library and take
complete control of the system.
The vulnerability is due to improper setting of the LD_LIBRARY_PATH environment. An attacker could exploit
this vulnerability by copying a malicious library onto the affected system's external memory and triggering
a reload of the system. An exploit could allow the attacker to force the affected system to load a malicious
library and access the underlying Linux OS, which could lead to a full compromise of the system." );
	script_tag( name: "impact", value: "A successful exploit could allow an authenticated, local attacker to
load a malicious library on the system and access the underlying Linux operating system, which could allow the
attacker to completely compromise the system." );
	script_tag( name: "affected", value: "Version 8.2, 8.3, 8.4 and 8.7" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=35914" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "8.2.5.52" ) < 0 ) && ( revcomp( a: compver, b: "8.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.2(5.52)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.4.3" ) < 0 ) && ( revcomp( a: compver, b: "8.3" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.4(3)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.7.1.13" ) < 0 ) && ( revcomp( a: compver, b: "8.7" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.7(1.13)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

