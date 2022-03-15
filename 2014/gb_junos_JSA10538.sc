CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105912" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-16 11:34:19 +0700 (Mon, 16 Jun 2014)" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos RDP Crash Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version" );
	script_tag( name: "summary", value: "RDP crash when receiving BGP UPDATE with malformed inetflow prefix." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "Receipt of a BGP UPDATE message containing a crafted flow specification
NLRI may cause RPD to crash. The update creates an invalid inetflow prefix which causes the RPD process
to allocate memory until it reaches its assigned memory limit." );
	script_tag( name: "impact", value: "After trying to exceed the process memory limit, RPD will crash and
restart. The system recovers after the crash, however a constant stream of malformed updates could cause
an extended outage." );
	script_tag( name: "affected", value: "Junos OS 10.0, 10.4, 11.4, 12.1 and 12.2." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper. As a
workaround disable the propagation of flow-specification NLRI messages via BGP by removing the flow
configuration option from protocols bgp ... family inet." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10538" );
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
if(revcomp( a: build2check, b: "20121005" ) >= 0){
	exit( 99 );
}
if(IsMatchRegexp( version, "^10" )){
	if( revcomp( a: version, b: "10.0S28" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "10.4R11" ) < 0 ) && ( revcomp( a: version, b: "10.1" ) >= 0 )){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^11" )){
	if(revcomp( a: version, b: "11.4R5" ) < 0){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1R3" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X44-D20" ) < 0 ) && ( revcomp( a: version, b: "12.1X44" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if( ( revcomp( a: version, b: "12.1X45-D10" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 ) ){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
			else {
				if(( revcomp( a: version, b: "12.2R1" ) < 0 ) && ( revcomp( a: version, b: "12.2" ) >= 0 )){
					security_message( port: 0, data: desc );
					exit( 0 );
				}
			}
		}
	}
}

