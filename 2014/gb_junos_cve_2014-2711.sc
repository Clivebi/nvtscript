CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105908" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-05-02 16:15:10 +0700 (Fri, 02 May 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-2711" );
	script_bugtraq_id( 66770 );
	script_name( "Junos J-Web Persistent Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version" );
	script_tag( name: "summary", value: "Persistent XSS Vulnerability in J-Web" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "A persistent cross site scripting vulnerability in J-Web may
allow a remote unauthenticated user to inject web script or HTML and steal sensitive data and credentials
from a J-Web session and to perform administrative actions on the Junos device. An attacker can inject
web script or HTML even when J-Web is disabled, but the vulnerability can only be exploited when J-Web is
used to monitor the system." );
	script_tag( name: "impact", value: "A remote unauthenticated user can inject web script or HTML and
steal sensitive data and credentials from a J-Web session and perform administrative
actions on the Junos device." );
	script_tag( name: "affected", value: "Junos OS 11.4, 12.1, 12.2, 12.3, 13.1, 13.2, 13.3." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10619" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66770" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
build = get_kb_item( "Junos/Build" );
if(!build){
	exit( 0 );
}
desc += "Version/Build-Date:
" + version + " / " + build;
build2check = str_replace( string: build, find: "-", replace: "" );
if(revcomp( a: build2check, b: "20140320" ) >= 0){
	exit( 99 );
}
if(revcomp( a: version, b: "11.4R11" ) < 0){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(( revcomp( a: version, b: "11.4X27.62" ) < 0 ) && ( revcomp( a: version, b: "11.4X" ) >= 0 )){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1R9" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X44-D35" ) < 0 ) && ( revcomp( a: version, b: "12.1X44" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if( ( revcomp( a: version, b: "12.1X45-D25" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 ) ){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
			else {
				if( ( revcomp( a: version, b: "12.1X46-D20" ) < 0 ) && ( revcomp( a: version, b: "12.1X46" ) >= 0 ) ){
					security_message( port: 0, data: desc );
					exit( 0 );
				}
				else {
					if( ( revcomp( a: version, b: "12.2R7" ) < 0 ) && ( revcomp( a: version, b: "12.2" ) >= 0 ) ){
						security_message( port: 0, data: desc );
						exit( 0 );
					}
					else {
						if(( revcomp( a: version, b: "12.3R6" ) < 0 ) && ( revcomp( a: version, b: "12.3" ) >= 0 )){
							security_message( port: 0, data: desc );
							exit( 0 );
						}
					}
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^13" )){
	if( revcomp( a: version, b: "13.1R4" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "13.2R3" ) < 0 ) && ( revcomp( a: version, b: "13.2" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "13.3R1" ) < 0 ) && ( revcomp( a: version, b: "13.3" ) >= 0 )){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

