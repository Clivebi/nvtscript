CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106180" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-17 11:04:27 +0700 (Wed, 17 Aug 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Zabbix Default Guest Account" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "zabbix_web_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Zabbix/Web/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Zabbix has a default guest account with no password set. It was possible
  to access the dashboard without special authentication." );
	script_tag( name: "vuldetect", value: "Tries to access the dashboard without credentials." );
	script_tag( name: "insight", value: "Initially Zabbix has a guest account with no password set but as well
  with no privileges on Zabbix objects which is used to access the user interface when no credentials are set." );
	script_tag( name: "impact", value: "An attacker may use this account to use further attacks to elevate
  his privileges." );
	script_tag( name: "solution", value: "Disable the guest account." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!location = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(location == "/"){
	location = "";
}
if(http_vuln_check( port: port, url: location + "/zabbix.php?action=dashboard.view", check_header: TRUE, pattern: "<title>Dashboard</title>", extra_check: "title=\"Sign out\"" )){
	report = http_report_vuln_url( port: port, url: location + "/zabbix.php?action=dashboard.view" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(http_vuln_check( port: port, url: location + "/dashboard.php", check_header: TRUE, pattern: "<title>.*Dashboard</title>", extra_check: "Connected as 'guest'" )){
	report = http_report_vuln_url( port: port, url: location + "/dashboard.php" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

