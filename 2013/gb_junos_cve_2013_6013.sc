if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103954" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-11-22 23:25:39 +0700 (Fri, 22 Nov 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2013-6013" );
	script_bugtraq_id( 62962 );
	script_name( "Junos flowd Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version" );
	script_tag( name: "summary", value: "A buffer overflow in the flow daemon when using telnet
pass-through authentication might lead to a complete compromise of the system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "Buffer overflow in the flow daemon (flowd) when using telnet
pass-through authentication on the firewall." );
	script_tag( name: "affected", value: "Platforms running Junos OS 10.4, 11.4, or 12.1X44." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper. As
a workaround disable telnet pass-through authentication if not required." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10594" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62962" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
version = get_kb_item( "Junos/Version" );
if(!version){
	exit( 0 );
}
build = get_kb_item( "Junos/Build" );
if(!build){
	exit( 0 );
}
desc += "Version/Build-Date:
" + version + " / " + build;
build2check = str_replace( string: build, find: "-", replace: "" );
if(revcomp( a: build2check, b: "20130711" ) >= 0){
	exit( 99 );
}
if(revcomp( a: version, b: "10.4S14" ) < 0){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(IsMatchRegexp( version, "^11" )){
	if(revcomp( a: version, b: "11.4R7-S2" ) < 0){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^12" )){
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
exit( 99 );

