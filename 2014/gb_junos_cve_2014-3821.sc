CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105919" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-07-31 13:16:56 +0200 (Thu, 31 Jul 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-3821" );
	script_bugtraq_id( 68548 );
	script_name( "Junos Web Authentication XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version", "Junos/model" );
	script_tag( name: "summary", value: "XSS vulnerability in webauth" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "A reflected cross site scripting (XSS) vulnerability in SRX Web
Authentication (webauth) may allow the stealing of sensitive information or session credentials from
firewall users. This issue affects the device only when Web Authentication is used for firewall user
authentication." );
	script_tag( name: "impact", value: "An attacker may steal sensitive information or session credentials
from firewall users." );
	script_tag( name: "affected", value: "Junos OS 11.4, 12.1X44, 12.1X45, 12.1X46" );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper. As
a workaround use Pass-Through Authentication rather than Web Authentication as an alternative form of
firewall user authentication." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10640" );
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
if(revcomp( a: version, b: "11.4R11" ) < 0){
	security_message( port: 0, data: version );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12\\.1X" )){
	if( revcomp( a: version, b: "12.1X44-D34" ) < 0 ){
		security_message( port: 0, data: version );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X45-D25" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 ) ){
			security_message( port: 0, data: version );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "12.1X46-D20" ) < 0 ) && ( revcomp( a: version, b: "12.1X46" ) >= 0 )){
				security_message( port: 0, data: version );
				exit( 0 );
			}
		}
	}
}

