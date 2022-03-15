CPE = "cpe:/a:icinga:icinga";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801866" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)" );
	script_bugtraq_id( 46788 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Icinga Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43643" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-001.txt" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-003.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_icinga_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "icinga/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Icinga versions 1.3.0 and prior." );
	script_tag( name: "insight", value: "- Input appended to the URL after 'cgi-bin/status.cgi' and
  'cgi-bin/notifications.cgi' is not properly sanitised before being returned to the user.

  - Input passed via the 'layer' parameter to 'cgi-bin/statusmap.cgi' is not
  properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Update to Icinga version 1.4.0 or later." );
	script_tag( name: "summary", value: "This host is running Icinga and is prone to multiple cross site
  scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
url = dir + "/cgi-bin/statusmap.cgi?layer=%27%20onmouseover=%22alert" + "(%27vt-xss-test%27)%22";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "alert\\('vt-xss-test'\\)" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

