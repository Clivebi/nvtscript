CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108193" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-18 11:54:29 +0200 (Tue, 18 Jul 2017)" );
	script_cve_id( "CVE-2017-2091", "CVE-2017-2092", "CVE-2017-2093", "CVE-2017-2094", "CVE-2017-2095" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-03 13:15:00 +0000 (Wed, 03 May 2017)" );
	script_name( "Cybozu Garoon Multiple Vulnerabilities - Apr17" );
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

  - bypass access restriction

  - to inject arbitrary web script or HTML

  - obtain tokens used for CSRF protection." );
	script_tag( name: "affected", value: "Cybozu Garoon 3.0.0 to 4.2.3." );
	script_tag( name: "solution", value: "Update to Cybozu Garoon 4.2.4 or later." );
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
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "4.2.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.2.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

