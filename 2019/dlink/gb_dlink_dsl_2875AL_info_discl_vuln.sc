if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142877" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2019-09-12 06:55:38 +0000 (Thu, 12 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "D-Link DSL-2875AL/DSL-2877AL Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dsl_device" );
	script_tag( name: "summary", value: "D-Link DSL-2875AL and DSL-2877AL are prone to an information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "It is possible to read the username and password used to connect to the ISP by
  examining the HTML code of /cgi-bin/index.asp." );
	script_tag( name: "affected", value: "D-Link DSL-2875AL prior to firmware version 1.00.08AU 20161011 and D-Link
  DSL-2877AL prior to firmware version 1.00.20AU 20180327." );
	script_tag( name: "solution", value: "Update firmware to version 1.00.08AU 20161011 (DSL-2875AL), 1.00.20AU 20180327
  (DSL-2877AL) or later." );
	script_xref( name: "URL", value: "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=26165" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
cpe_list = make_list( "cpe:/o:d-link:dsl-2875al_firmware",
	 "cpe:/o:d-link:dsl-2877al_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www" )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/cgi-bin/index.asp";
if(http_vuln_check( port: port, url: url, pattern: "var username_v = '", check_header: TRUE, extra_check: "var password_v = '" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

