CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106029" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-07-15 12:04:27 +0700 (Wed, 15 Jul 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-4238" );
	script_name( "Cisco ASA SNMP DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "Cisco ASA is prone to an SNMP Denial of Service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of SNMP packets.
An attacker could exploit this vulnerability by sending a high rate of traffic through the device while
performing SNMP operations continuously." );
	script_tag( name: "impact", value: "An authenticated, remote attacker could exploit this vulnerability
by sending a high rate of traffic through the device while performing SNMP operations continuously. A
successful exploit could result in a DoS condition." );
	script_tag( name: "affected", value: "Version 8.4 and 8.6" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=39611" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "8.4.7" ) <= 0 ) && ( revcomp( a: compver, b: "8.4" ) >= 0 )){
	security_message( port: 0 );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.6.1.2" ) <= 0 ) && ( revcomp( a: compver, b: "8.6" ) >= 0 )){
	security_message( port: 0 );
	exit( 0 );
}
exit( 0 );

