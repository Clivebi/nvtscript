CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103967" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-01-15 15:11:43 +0700 (Wed, 15 Jan 2014)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-0618" );
	script_bugtraq_id( 64769 );
	script_name( "Junos Denial of Service Vulnerability while Processing HTTP Traffic" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version", "Junos/model" );
	script_tag( name: "summary", value: "Denial of Service vulnerability in flowd while processing valid
HTTP traffic." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "On SRX Series services gateways acting as UAC enforcer with
captive portal enabled, certain valid HTTP protocol messages may cause the flow daemon process to crash." );
	script_tag( name: "impact", value: "Remote attackers can cause a denial of service condition on the
device." );
	script_tag( name: "affected", value: "Junos OS 10.4, 11.4, 12.1 and 12.1X44." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10611" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64769" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
model = get_kb_item( "Junos/model" );
if(!model || !ContainsString( toupper( model ), "SRX" )){
	exit( 99 );
}
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
if(revcomp( a: build2check, b: "20131212" ) >= 0){
	exit( 99 );
}
if(revcomp( a: version, b: "10.4R16" ) < 0){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(IsMatchRegexp( version, "^11" )){
	if(revcomp( a: version, b: "11.4R8" ) < 0){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1R7" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X44-D20" ) < 0 ) && ( revcomp( a: version, b: "12.1X" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "12.1X45-D10" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 )){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

