CPE = "cpe:/a:cybozu:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107149" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-19 14:53:28 +0200 (Wed, 19 Apr 2017)" );
	script_cve_id( "CVE-2017-2114", "CVE-2017-2115", "CVE-2017-2116", "CVE-2016-4449" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-18 18:18:00 +0000 (Thu, 18 Jan 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozu Office Multiple Security Vulnerabilities" );
	script_tag( name: "summary", value: "Cybozu Office is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, access or modify data, bypass security restrictions and perform unauthorized
  actions in the context of the affected application." );
	script_tag( name: "affected", value: "Cybozu Office 10.0.0 through 10.5.0 are vulnerable" );
	script_tag( name: "solution", value: "Update to version 10.6.0." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/97717" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuOffice/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!Ver = get_app_version( port: Port, cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( Ver, "^10\\." )){
	if(version_is_less_equal( version: Ver, test_version: "10.5.0" )){
		report = report_fixed_ver( installed_version: Ver, fixed_version: "10.6.0" );
		security_message( port: Port, data: report );
		exit( 0 );
	}
}
exit( 99 );

