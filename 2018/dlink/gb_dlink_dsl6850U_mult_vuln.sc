CPE_PREFIX = "cpe:/o:d-link";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812376" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-01-03 15:39:16 +0530 (Wed, 03 Jan 2018)" );
	script_name( "D-Link DSL-6850U Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://blogs.securiteam.com/index.php/archives/3588" );
	script_tag( name: "summary", value: "The host is a D-Link DSL-6850U router
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request
  and check whether it is possible to access the administration GUI or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Default account 'support' with password 'support' which cannot be disabled.

  - Availability of the shell interface although only a set of commands, but
  commands can be combined using logical AND, logical OR." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to access administration of the device and execute arbitrary code
  on the affected system." );
	script_tag( name: "affected", value: "D-Link DSL-6850U versions BZ_1.00.01 - BZ_1.00.09.
  Other devices, models or versions might be also affected." );
	script_tag( name: "solution", value: "Apply the latest security patches from the
  vendor." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/lainterface.html";
res = http_get_cache( item: url, port: port );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
	exit( 0 );
}
host = http_host_name( port: port );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic c3VwcG9ydDpzdXBwb3J0\\r\\n", "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(res && ContainsString( res, "WAN SETTINGS" ) && ContainsString( res, "value='3G Interface" ) && ContainsString( res, "menu.html" ) && ContainsString( res, "TabHeader=th_setup" ) && ContainsString( res, "src=\"util.js\"" ) && ContainsString( res, "src=\"language_en.js\"" )){
	report = "It was possible to login with the default account 'support:support' at the following URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

