CPE = "cpe:/a:ui:unifi_protect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144407" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-18 05:41:59 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-05 18:51:00 +0000 (Wed, 05 Aug 2020)" );
	script_cve_id( "CVE-2020-8213" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "UniFi Protect <= 1.13.3 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ui_unifi_protect_ubnt_detect.sc" );
	script_mandatory_keys( "ui/unifi_protect/detected" );
	script_tag( name: "summary", value: "UniFi Protect is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An information exposure vulnerability exists in UniFi Protect that allows
  unauthenticated attackers access to valid usernames for the UniFi Protect web application via HTTP response code
  and response timing." );
	script_tag( name: "affected", value: "UniFi Protect version 1.13.3 and prior." );
	script_tag( name: "solution", value: "Update to version 1.13.4-beta.5 or later." );
	script_xref( name: "URL", value: "https://community.ui.com/releases/Security-advisory-bulletin-013-013/56d4d616-4afd-40ee-863f-319b7126ed84" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "1.13.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.13.4-beta.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

