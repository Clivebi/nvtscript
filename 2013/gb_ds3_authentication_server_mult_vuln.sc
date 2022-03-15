if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803710" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-06-04 13:59:02 +0530 (Tue, 04 Jun 2013)" );
	script_name( "DS3 Authentication Server Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/526784/30/0/threaded" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121862/ds3authserv-exec.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/ds3-authentication-server-command-execution" );
	script_cve_id( "CVE-2013-4096", "CVE-2013-4097", "CVE-2013-4098" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to:

  - The TestTelnetConnection.jsp does not validate the user input, allowing
  an attacker to execute arbitrary commands in the server side with the
  privileges of asadmin user.

  - TestDRConnection.jsp, shows the file path in the error messages, this is
  considered a minor information leak.

  - Without being authenticated, any user is able to manipulate the message
  of the default error page, helping him to develop social engineering
  attacks.

  - ServerAdmin/ErrorViewer.jsp in DS3 Authentication Server allow remote attackers to inject arbitrary error-page text via the message parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "This host is running DS3 Authentication Server and is prone to
  multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to
  execute arbitrary commands and obtain the sensitive information." );
	script_tag( name: "affected", value: "DS3 Authentication Server" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( item: "/ServerAdmin/UserLogin.jsp", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && ContainsString( res, "Server: DS3-AuthServer" )){
	url = "/ServerAdmin/ErrorViewer.jsp?message=Message";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && ContainsString( res, ">Error Page<" ) && ContainsString( res, ">Error Message:" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

