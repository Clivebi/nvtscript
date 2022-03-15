CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105981" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-13 12:14:11 +0700 (Fri, 13 Mar 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-3387" );
	script_bugtraq_id( 70303 );
	script_name( "Cisco ASA SunRPC Inspection Engine DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "The SunRPC Inspection Engine of Cisco ASA is prone to a Denial of
Service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the SunRPC inspection engine of Cisco ASA
Software could allow an unauthenticated, remote attacker to cause the reload of an affected system.
The vulnerability is due to insufficient validation of crafted SunRPC packets. An attacker could exploit
this vulnerability by sending crafted SunRPC packets through the affected system." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker could exploit this vulnerability
by sending crafted SunRPC packets through a targeted device. An exploit could allow the attacker to cause
the device to reload, resulting in a DoS condition." );
	script_tag( name: "affected", value: "Version 7.2, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 9.0 and 9.1" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=35910" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
version = get_kb_item( "cisco_asa/version" );
if(!version){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "7.2.5.14" ) < 0 ) && ( revcomp( a: compver, b: "7.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     7.2(5.14)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.2.5.51" ) < 0 ) && ( revcomp( a: compver, b: "8.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.2(5.51)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.3.2.42" ) < 0 ) && ( revcomp( a: compver, b: "8.3" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.3(2.42)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.4.7.23" ) < 0 ) && ( revcomp( a: compver, b: "8.4" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.4(7.23)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.5.1.21" ) < 0 ) && ( revcomp( a: compver, b: "8.5" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.5(1.21)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.6.1.14" ) < 0 ) && ( revcomp( a: compver, b: "8.6" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.6(1.14)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.7.1.13" ) < 0 ) && ( revcomp( a: compver, b: "8.7" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.7(1.13)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.0.4.5" ) < 0 ) && ( revcomp( a: compver, b: "9.0" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.0(4.5)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.1.5.3" ) < 0 ) && ( revcomp( a: compver, b: "9.1" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.1(5.3)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

