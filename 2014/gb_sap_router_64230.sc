CPE = "cpe:/a:sap:network_interface_router";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105035" );
	script_version( "2021-04-27T06:43:32+0000" );
	script_bugtraq_id( 64230 );
	script_cve_id( "CVE-2013-7093" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-27 06:43:32 +0000 (Tue, 27 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-27 15:35:11 +0200 (Tue, 27 May 2014)" );
	script_name( "SAProuter Remote Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "General" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_sap_router_detect.sc" );
	script_require_ports( "Services/SAProuter", 3299 );
	script_mandatory_keys( "SAProuter/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64230" );
	script_xref( name: "URL", value: "https://erpscan.io/advisories/erpscan-13-023-saprouter-authentication-bypass/" );
	script_xref( name: "URL", value: "https://launchpad.support.sap.com/#/notes/1853140" );
	script_tag( name: "summary", value: "SAProuter is prone to an authentication-bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Sends an information request and checks the response." );
	script_tag( name: "insight", value: "An attacker can reconfigure SAProuter remotely without
  authentication because authorization check is missing. It can lead to various threats, from
  information disclosure to full system compromise." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to bypass the authentication
  mechanism and gain unauthorized access." );
	script_tag( name: "affected", value: "SAP Network Interface Router (SAProuter) 39.3 SP4." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
req = raw_string( 0x00, 0x00, 0x00, 0x0f, "ROUTER_ADM\0", 39, 0x02, 0x00, 0x00 );
send( socket: soc, data: req );
for(;TRUE;){
	buf = recv( socket: soc, min: 4, length: 4 );
	if(!buf || strlen( buf ) != 4){
		close( soc );
		exit( 0 );
	}
	len = getdword( blob: buf );
	if(!len || int( len ) < 1){
		break;
	}
	buf = recv( socket: soc, length: len );
	if(!buf || ContainsString( buf, "NI_RTERR" ) || strlen( buf ) != len){
		close( soc );
		exit( 99 );
	}
	if(IsMatchRegexp( buf, "[:^cntrl:]+" )){
		report += substr( buf, 0, strlen( buf ) - 2 ) + "\n";
	}
}
close( soc );
if(report){
	report = "The following information could be gathered by the scanner:\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

