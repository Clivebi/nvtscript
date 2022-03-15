if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114134" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2019-09-25 12:50:05 +0200 (Wed, 25 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "D-Link DSL-2875AL Password Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dsl_device" );
	script_tag( name: "summary", value: "D-Link DSL-2875AL is prone to a password disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "It is possible to acquire lots of information about all accounts and the network,
  including usernames and their passwords in plaintext by examining the response for /romfile.cfg." );
	script_tag( name: "affected", value: "D-Link DSL-2875AL firmware versions 1.00.01, 1.00.05 and most likely others." );
	script_tag( name: "solution", value: "Update firmware to version 1.00.08AU 20161011 or later." );
	script_xref( name: "URL", value: "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=26165" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
CPE = "cpe:/o:d-link:dsl-2875al_firmware";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/romfile.cfg";
if(http_vuln_check( port: port, url: url, pattern: "<Account>", extra_check: "web_passwd=" )){
	report = "It was possible to access sensitive user information through: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

