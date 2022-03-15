CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105913" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-19 10:58:12 +0700 (Thu, 19 Jun 2014)" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:M/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Exclusive Edit Mode Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version" );
	script_tag( name: "summary", value: "Privilege Escalation in exclusive edit mode" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "An escalation of privileges can occur when the 'load factory-default'
command fails while in exclusive edit mode. When the load command fails, the user is no longer subject
to any command and/or configuration restrictions. The escalation is limited to authenticated users with
the ability to edit the configuration in the first place. The privilege bypass is specific to configured
classes of CLI users with restrictions such as 'allow-commands', 'deny-commands', and 'deny-configuration'." );
	script_tag( name: "impact", value: "Authenticated users with the ability to edit the configuration can
bypass CLI restrictions." );
	script_tag( name: "affected", value: "Junos OS 10.0, 10.4, 11.2, 11.3, 11.4 and 12.1." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper. As a
workaround deny access to the 'load factory-default' command." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10520" );
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
if(revcomp( a: build2check, b: "20120601" ) >= 0){
	exit( 99 );
}
if(revcomp( a: version, b: "10.0S26" ) < 0){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(( revcomp( a: version, b: "10.4R10" ) < 0 ) && ( revcomp( a: version, b: "10.1" ) >= 0 )){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(IsMatchRegexp( version, "^11" )){
	if( revcomp( a: version, b: "11.2R7" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "11.3R6" ) < 0 ) && ( revcomp( a: version, b: "11.3" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "11.4R3" ) < 0 ) && ( revcomp( a: version, b: "11.4" ) >= 0 )){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
		}
	}
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1R2" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X44-D15" ) < 0 ) && ( revcomp( a: version, b: "12.1X44" ) >= 0 ) ){
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

