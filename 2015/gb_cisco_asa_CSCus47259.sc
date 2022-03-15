CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106012" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-23 09:56:22 +0700 (Tue, 23 Jun 2015)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-0760" );
	script_bugtraq_id( 74957 );
	script_name( "Cisco ASA XAUTH Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "Cisco ASA is prone to a XAUTH bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in IKE version 1 code of Cisco ASA Software
could allow an authenticated, remote attacker to bypass Extended Authentication (XAUTH) and successfully
log in via IPsec remote VPN. The vulnerability is due to improper implementation of the logic of the
XAUTH code." );
	script_tag( name: "impact", value: "An authenticated, remote attacker could exploit this vulnerability
to bypass authentication and gain network access to an environment an affected device is protecting. A
successful exploit could be used to conduct further attacks." );
	script_tag( name: "affected", value: "Version 7.x, 8.0, 8.1 and 8.2" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=39157" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "7.2.5.16" ) < 0 ) && ( revcomp( a: compver, b: "7" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     7.2(5.16)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.0.5.17" ) < 0 ) && ( revcomp( a: compver, b: "8.0" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.0(5.17)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.1.2.45" ) < 0 ) && ( revcomp( a: compver, b: "8.1" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.1(2.45)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "8.2.2.13" ) < 0 ) && ( revcomp( a: compver, b: "8.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.2(2.13)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

