CPE = "cpe:/a:cisco:asa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105986" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-03-13 13:31:53 +0700 (Fri, 13 Mar 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-3393" );
	script_bugtraq_id( 70309 );
	script_name( "Cisco ASA Clientless SSL VPN Portal Customization Integrity Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_asa_version.sc", "gb_cisco_asa_version_snmp.sc" );
	script_mandatory_keys( "cisco_asa/version" );
	script_tag( name: "summary", value: "The Clientless SSL VPN Portal of Cisco ASA is prone to a customization
integrity vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the Clientless SSL VPN portal customization framework
could allow an unauthenticated, remote attacker to modify the content of the Clientless SSL VPN portal, which
could lead to several attacks including the stealing of credentials, cross-site scripting (XSS), and other types
of web attacks on the client using the affected system.
The vulnerability is due to an improper implementation of authentication checks in the Clientless SSL VPN portal
customization framework." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker could exploit this vulnerability by
modifying some of the customization objects in the RAMFS cache file system. An exploit could allow the attacker
to bypass Clientless SSL VPN authentication and modify the portal content. If successful, the attacker could
conduct web-based attacks against a client using the affected software, which could be used to access sensitive
information." );
	script_tag( name: "affected", value: "Version 8.2, 8.3, 8.4, 8.6, 9.0, 9.1 and 9.2" );
	script_tag( name: "solution", value: "Apply the appropriate updates from Cisco." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=35917" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
compver = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
if(( revcomp( a: compver, b: "8.2.5.51" ) < 0 ) && ( revcomp( a: compver, b: "8.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.0(4.13)\n";
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
if(( revcomp( a: compver, b: "8.6.1.14" ) < 0 ) && ( revcomp( a: compver, b: "8.6" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     8.6(1.14)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.0.4.24" ) < 0 ) && ( revcomp( a: compver, b: "9.0" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.0(4.24)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.1.5.12" ) < 0 ) && ( revcomp( a: compver, b: "9.1" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.1(5.12)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
if(( revcomp( a: compver, b: "9.2.2.4" ) < 0 ) && ( revcomp( a: compver, b: "9.2" ) >= 0 )){
	report = "Installed Version: " + version + "\n" + "Fixed Version:     9.2(2.4)\n";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

