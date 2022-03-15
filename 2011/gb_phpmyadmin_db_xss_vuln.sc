CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801851" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "phpMyAdmin 'db' Parameter Stored Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/97906/phpmyadmin34-xss.txt" );
	script_xref( name: "URL", value: "http://bl0g.yehg.net/2011/01/phpmyadmin-34x-340-beta-2-stored-cross.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to plant XSS backdoors and
  inject arbitrary SQL statements via crafted XSS payloads." );
	script_tag( name: "affected", value: "phpMyAdmin versions 3.4.x before 3.4.0 beta 3" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed in
  the 'db' parameter to 'index.php', which allows attackers to execute arbitrary
  HTML and script code on the web server." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 3.4.0 beta 3 or later." );
	script_tag( name: "summary", value: "The host is running phpMyAdmin and is prone to Cross-Site Scripting
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = NASLString( dir, "/index.php?db=%27%22--%3E%3C%2Fscript%3E%3Cscript%3Ealert%" + "28%2FXSS%2F%29%3C%2Fscript%3E" );
if(buf = http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/XSS/\\)</", check_header: TRUE )){
	if(ContainsString( buf, "\"--" )){
		exit( 99 );
	}
	security_message( port );
}

