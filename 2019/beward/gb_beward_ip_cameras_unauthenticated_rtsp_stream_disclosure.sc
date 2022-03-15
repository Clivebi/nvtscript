if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114076" );
	script_version( "2021-02-25T16:05:56+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-25 16:05:56 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 14:56:16 +0100 (Tue, 26 Feb 2019)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_name( "Beward IP Camera Unauthenticated RTSP Stream Disclosure Vulnerability" );
	script_dependencies( "gb_beward_ip_camera_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "beward/ip_camera/detected" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5509.php" );
	script_tag( name: "summary", value: "The remote installation of Beward's IP camera software is prone to
  an unauthenticated and unauthorized live RTSP video stream disclosure vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  gain information, depending on what the camera is used for." );
	script_tag( name: "insight", value: "Some hosts expose their RTSP video stream to the public by
  allowing unauthenticated users to access the /cgi-bin/view/image page." );
	script_tag( name: "vuldetect", value: "Checks if the host responds with an image." );
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
url = "/cgi-bin/view/image";
req = http_get_req( port: port, url: url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Content-type: image/jpeg" ) && !ContainsString( res, "Your client does not have permission" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

