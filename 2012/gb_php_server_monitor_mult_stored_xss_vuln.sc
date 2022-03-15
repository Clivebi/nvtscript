CPE = "cpe:/a:phpserver:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803109" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2012-11-22 12:51:18 +0530 (Thu, 22 Nov 2012)" );
	script_bugtraq_id( 56622 );
	script_name( "PHP Server Monitor Multiple Stored Cross-Site Scripting Vulnerabilities" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_server_monitor_detect.sc" );
	script_mandatory_keys( "PHP/Server/Monitor/Installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to execute
  arbitrary code in the context of an application." );
	script_tag( name: "affected", value: "PHP Server Monitor version 2.1.0 and prior" );
	script_tag( name: "insight", value: "The flaws are due improper validation of user-supplied input
  passed via the 'label' and 'name' parameter to 'index.php', that allows
  attackers to execute arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "Upgrade to version 3.0.0 or higher." );
	script_tag( name: "summary", value: "This host is installed with PHP Server Monitor and is prone to
  multiple stored cross-site scripting vulnerabilities." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/22881/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56622" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118254/PHP-Server-Monitor-Cross-Site-Scripting.html" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
ver = infos["version"];
dir = infos["location"];
if( dir != NULL && !safe_checks() ){
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php?type=servers";
	req = http_post( port: port, item: url, data: "label=%3Cscript%3Ealert%28document.cookie%29%3B%3C%2F" + "script%3E&ip=&port=&type=service&active=yes&email=yes" + "&sms=yes&server_id=0&submit=Save" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie);</script>" ) && ContainsString( res, ">Add new?<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: ver, test_version: "3.0.0" )){
		report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.0", install_url: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

