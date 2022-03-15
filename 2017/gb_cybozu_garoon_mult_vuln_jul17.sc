CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108194" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-18 11:54:29 +0200 (Tue, 18 Jul 2017)" );
	script_cve_id( "CVE-2017-2144", "CVE-2017-2145", "CVE-2017-2146" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Cybozu Garoon Multiple Vulnerabilities - Jul17" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_tag( name: "summary", value: "This host is installed with Cybozu Garoon
  and is vulnerable to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cybozu Garoon is prone to multiple vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated attackers to:

  - to lock another user's file through a specially crafted page

  - to perform arbitrary operations via unspecified vectors

  - inject arbitrary web script or HTML via application menu." );
	script_tag( name: "affected", value: "Cybozu Garoon 3.0.0 to 4.2.4." );
	script_tag( name: "solution", value: "Update to Cybozu Garoon 4.2.5 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "4.2.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.2.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

