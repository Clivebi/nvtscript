if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103949" );
	script_version( "$Revision: 12095 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-28 12:53:03 +0700 (Mon, 28 Oct 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2013-6170" );
	script_bugtraq_id( 62973 );
	script_name( "Junos PIM Join Flooding Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Build", "Junos/Version" );
	script_tag( name: "summary", value: "A large number of crafted PIM join messages can crash the RPD
routing daemon." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "Receipt of a large number of crafted IPv4 or IPv6 PIM join
messages in a Next-Generation Multicast VPN (NGEN MVPN) environment can trigger the RPD routing daemon
to crash." );
	script_tag( name: "impact", value: "Once a large amount of these PIM joins are received by the
router, RPD crashes and restarts." );
	script_tag( name: "affected", value: "Junos OS 10.0 or later but only applies to PIM in an NGEN MVPN
environment." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper. As
a workaround ACLs or firewall filters to limit PIM access to the router only from trusted hosts." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10548" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62973" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55216" );
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
if(revcomp( a: build2check, b: "20120927" ) >= 0){
	exit( 99 );
}
if(revcomp( a: version, b: "10.0S28" ) < 0){
	security_message( port: 0, data: desc );
	exit( 0 );
}
if(IsMatchRegexp( version, "^10" )){
	if(revcomp( a: version, b: "10.4R7" ) < 0){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^11" )){
	if( revcomp( a: version, b: "11.1R5" ) < 0 ){
		security_message( port: 0, data: desc );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "11.2R2" ) < 0 ) && ( revcomp( a: version, b: "11.2" ) >= 0 ) ){
			security_message( port: 0, data: desc );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "11.4R1" ) < 0 ) && revcomp( a: version, b: "11.4" ) >= 0){
				security_message( port: 0, data: desc );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

