CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106796" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-28 08:43:22 +0200 (Fri, 28 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-2824", "CVE-2017-2825" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zabbix Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	script_tag( name: "summary", value: "Zabbix is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Zabbix is prone to multiple vulnerabilities:

  - Zabbix Server Active Proxy Trapper Remote Code Execution Vulnerability (CVE-2017-2824)

  - Zabbix Proxy Server SQL Database Write Vulnerability (CVE-2017-2825)" );
	script_tag( name: "impact", value: "An unauthenticated attacker may execute arbitrary code." );
	script_tag( name: "affected", value: "Zabbix version prior to 2.0.21, 2.2.x, 3.0.x and 3.2.x." );
	script_tag( name: "solution", value: "Update to 2.0.21, 2.2.18, 3.0.9, 3.2.5 or newer versions." );
	script_xref( name: "URL", value: "http://blog.talosintelligence.com/2017/04/zabbix-multiple-vulns.html" );
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
if(version_is_less( version: version, test_version: "2.0.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.21" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\.2" )){
	if(version_is_less( version: version, test_version: "2.2.18" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.2.18" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^3\\.0" )){
	if(version_is_less( version: version, test_version: "3.0.9" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "3.0.9" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^3\\.2" )){
	if(version_is_less( version: version, test_version: "3.2.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "3.2.5" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

