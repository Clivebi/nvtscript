CPE = "cpe:/a:livezilla:livezilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901172" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-01-03 16:00:43 +0100 (Mon, 03 Jan 2011)" );
	script_cve_id( "CVE-2010-4276" );
	script_bugtraq_id( 45586 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "LiveZilla 'Track' Module 'server.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2010/Dec/650" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3331" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_livezilla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "LiveZilla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "LiveZilla version 3.2.0.2." );
	script_tag( name: "insight", value: "The flaw is caused by an input validation error in the 'server.php'
  script when processing user-supplied data, which could be exploited by attackers
  to cause arbitrary scripting code to be executed by the user's browser in the
  security context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running LiveZilla and is prone to Cross-Site Scripting
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/server.php?request=track&livezilla=<script>alert(\'xss\')</script>";
if(http_vuln_check( port: port, url: url, pattern: "&lt;script&gt;alert\\('xss'\\)" + "&lt;/script&gt", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

