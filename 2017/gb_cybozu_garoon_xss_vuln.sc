CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811592" );
	script_version( "2021-09-17T08:26:11+0000" );
	script_cve_id( "CVE-2017-2255" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 08:26:11 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-30 14:45:00 +0000 (Wed, 30 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-09-01 11:50:27 +0530 (Fri, 01 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozu Garoon 'Rich text' Function XSS Vulnerability" );
	script_tag( name: "summary", value: "Cybozu Garoon is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Stored cross-site scripting in the 'Rich text' function
  of the application 'Space'" );
	script_tag( name: "impact", value: "An arbitrary script may be executed on the logged-in user's
  web browser." );
	script_tag( name: "affected", value: "Cybozu Garoon 3.7.0 to 4.2.5." );
	script_tag( name: "solution", value: "Update to the Cybozu Garoon version 4.2.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN63564682/index.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_xref( name: "URL", value: "https://cs.cybozu.co.jp/2017/006442.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cyPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cyVer = get_app_version( cpe: CPE, port: cyPort )){
	exit( 0 );
}
if(version_in_range( version: cyVer, test_version: "3.7.0", test_version2: "4.2.5" )){
	report = report_fixed_ver( installed_version: cyVer, fixed_version: "4.2.6 or later" );
	security_message( data: report, port: cyPort );
	exit( 0 );
}
exit( 0 );

