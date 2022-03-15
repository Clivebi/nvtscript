if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113402" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-29 14:22:26 +0000 (Wed, 29 May 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-17 18:20:00 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-5947" );
	script_name( "Cybozu Garoon >= 4.6.0, <= 4.10.1 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_tag( name: "summary", value: "Cybozu Garoon is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists within the application 'Cabinet'." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to inject arbitrary
  web script or HTML into the site." );
	script_tag( name: "affected", value: "Cybozu Garoon versions 4.6.0 through 4.10.1." );
	script_tag( name: "solution", value: "Update to version 4.10.2." );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN58849431/index.html" );
	script_xref( name: "URL", value: "https://kb.cybozu.support/article/35496/" );
	exit( 0 );
}
CPE = "cpe:/a:cybozu:garoon";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "4.6.0", test_version2: "4.10.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.10.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

