if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804875" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-7292" );
	script_bugtraq_id( 70654 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-04 11:40:26 +0530 (Tue, 04 Nov 2014)" );
	script_name( "Newtelligence dasBlog 'url' Parameter Open Redirect Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/97667" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128749" );
	script_xref( name: "URL", value: "http://www.tetraph.com/blog/cves/cve-2014-7292-newtelligence-dasblog-open-redirect-vulnerability/" );
	script_tag( name: "summary", value: "This host is installed with Newtelligence
  dasBlog and is prone to open redirect vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites." );
	script_tag( name: "insight", value: "The error exists as the application does not
  validate the 'url' parameter upon submission to the ct.ashx script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing." );
	script_tag( name: "affected", value: "Newtelligence dasBlog versions
  2.1 (2.1.8102.813), 2.2 (2.2.8279.16125), and 2.3 (2.3.9074.18820)." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
blogPort = http_get_port( default: 80 );
if(!http_can_host_asp( port: blogPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/dasBlog", "/blog", "/", http_cgi_dirs( port: blogPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/Login.aspx", port: blogPort );
	if(rcvRes && IsMatchRegexp( rcvRes, "Powered by.*newtelligence dasBlog" )){
		url = dir + "/ct.ashx?&url=http://www.example.com";
		sndReq = http_get( item: url, port: blogPort );
		rcvRes = http_keepalive_send_recv( port: blogPort, data: sndReq );
		if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 302" ) && ContainsString( rcvRes, "Location: http://www.example.com" )){
			report = http_report_vuln_url( port: blogPort, url: url );
			security_message( port: blogPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

