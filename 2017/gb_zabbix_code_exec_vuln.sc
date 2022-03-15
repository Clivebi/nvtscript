CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106545" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-26 14:54:40 +0700 (Thu, 26 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)" );
	script_cve_id( "CVE-2016-4338" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zabbix Arbitrary Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "summary", value: "Zabbix is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The mysql user parameter configuration script (userparameter_mysql.conf),
when used with a shell other than bash, allows context-dependent attackers to execute arbitrary code or SQL
commands via the mysql.size parameter." );
	script_tag( name: "affected", value: "Zabbix version prior to 2.0.18, 2.2.x and 3.0.x" );
	script_tag( name: "solution", value: "Update to 2.0.18, 2.2.13, 3.0.3 or newer versions." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/136898/Zabbix-Agent-3.0.1-mysql.size-Shell-Command-Injection.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.0.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.18" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\.2" )){
	if(version_is_less( version: version, test_version: "2.2.13" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.2.13" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^3\\.0" )){
	if(version_is_less( version: version, test_version: "3.0.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "3.0.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

