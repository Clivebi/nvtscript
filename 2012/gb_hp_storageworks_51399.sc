if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103431" );
	script_bugtraq_id( 51399 );
	script_cve_id( "CVE-2011-4788", "CVE-2012-0697" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_name( "HP StorageWorks Default Accounts and Directory Traversal Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-21 13:19:06 +0100 (Tue, 21 Feb 2012)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51399" );
	script_xref( name: "URL", value: "http://h10010.www1.hp.com/wwpc/us/en/sm/WF05a/12169-304616-241493-241493-241493-3971478.html" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-12-015/" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/885499" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "ssh_detect.sc", "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80, "Services/ssh", 22, "Services/telnet", 23 );
	script_mandatory_keys( "WindRiver-WebServer/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "An attacker could exploit these issues to access arbitrary files on
  the affected computer, or gain administrative access to the affected application. This may aid in
  the compromise of the underlying computer." );
	script_tag( name: "affected", value: "HP StorageWorks P2000 G3 is affected." );
	script_tag( name: "solution", value: "The vendor released an update to address this issue. Please see the
  references for more information." );
	script_tag( name: "summary", value: "HP StorageWorks is prone to a security-bypass vulnerability and a directory-
  traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("telnet_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ports = http_get_ports( default_port_list: make_list( 80 ) );
for port in ports {
	banner = http_get_remote_headers( port: port );
	if(!banner || !ContainsString( banner, "WindRiver-WebServer" )){
		continue;
	}
	buf = http_get_cache( item: "/", port: port );
	if(ContainsString( buf, "<title>HP StorageWorks" )){
		found = TRUE;
		break;
	}
}
if(found){
	credentials = make_array( "monitor", "!monitor", "manage", "!manage", "ftp", "!ftp" );
	ports = telnet_get_ports( default: 23 );
	for port in ports {
		for credential in keys( credentials ) {
			if(!soc = open_sock_tcp( port )){
				break;
			}
			user = credential;
			pass = credentials[credential];
			b = telnet_negotiate( socket: soc );
			if(!ContainsString( b, "Login" )){
				close( soc );
				break;
			}
			send( socket: soc, data: NASLString( user, "\\r\\n" ) );
			answer = recv( socket: soc, length: 4096 );
			send( socket: soc, data: NASLString( pass, "\\r\\n" ) );
			answer = recv( socket: soc, length: 4096 );
			close( soc );
			if(ContainsString( answer, "StorageWorks" ) && ContainsString( answer, "System Name" )){
				report = "It was possible to login via telnet using \"" + user + "\" as username and \"" + pass + "\" as password.";
				security_message( port: port, data: report );
				break;
			}
		}
	}
	port = ssh_get_port( default: 22 );
	for credential in keys( credentials ) {
		if(!soc = open_sock_tcp( port )){
			break;
		}
		user = credential;
		pass = credentials[credential];
		login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
		close( soc );
		if(login == 0){
			report = "It was possible to login via ssh using \"" + user + "\" as username and \"" + pass + "\" as password.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	exit( 99 );
}
exit( 0 );

