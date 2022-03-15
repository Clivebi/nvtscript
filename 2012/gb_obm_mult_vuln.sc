if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803027" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2011-5141", "CVE-2011-5142", "CVE-2011-5143", "CVE-2011-5144", "CVE-2011-5145" );
	script_bugtraq_id( 51153 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-09-18 11:33:54 +0530 (Tue, 18 Sep 2012)" );
	script_name( "Open Business Management Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47139" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71924" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23060" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to cause SQL
  injection attack, gain sensitive information and execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site." );
	script_tag( name: "affected", value: "Open Business Management (OBM) 2.4.0-rc13 and prior" );
	script_tag( name: "insight", value: "Multiple vulnerabilities due to:

  - Improper access restrictions to the 'test.php' script allowing
  attackers to obtain configuration information via a direct request to
  test.php, which calls the phpinfo function.

  - Input passed via the 'sel_domain_id' and 'action' parameters to 'obm.php'
  is not properly sanitised before being used in SQL queries.

  - Input passed via the 'tf_user' parameter to group/group_index.php and
  'tf_name', 'tf_delegation', and 'tf_ip' parameters to host/host_index.php
  is not properly sanitised before being used in SQL queries.

  - Input passed to the 'tf_name', 'tf_delegation', and 'tf_ip' parameters in
  index.php, 'login' parameter in obm.php, and 'tf_user' parameter in
  group/group_index.php is not properly sanitised before being returned
  to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Open Business Management and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/", "/obm", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	if(http_vuln_check( port: port, url: dir + "/obm.php", check_header: TRUE, pattern: "<title>.* OBM", extra_check: "OBM.org" )){
		url = dir + "/test.php";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<title>phpinfo()", extra_check: make_list( ">System <",
			 ">Configuration<",
			 ">PHP Core<" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

