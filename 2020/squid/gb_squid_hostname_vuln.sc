CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143623" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-03-23 04:00:09 +0000 (Mon, 23 Mar 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-22 15:15:00 +0000 (Wed, 22 Jul 2020)" );
	script_cve_id( "CVE-2019-18860" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache < 4.9 Hostname Validation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid, when certain web browsers are used, mishandles HTML in the host (aka
  hostname) parameter to cachemgr.cgi." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions prior to version 4.9." );
	script_tag( name: "solution", value: "Update to version 4.9 or later." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/pull/504" );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/pull/505" );
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
if(version_is_less( version: version, test_version: "4.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

