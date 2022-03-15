CPE = "cpe:/a:cybozu:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813617" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0526", "CVE-2018-0527", "CVE-2018-0528", "CVE-2018-0529" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-08 18:03:00 +0000 (Wed, 08 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-27 11:07:13 +0530 (Wed, 27 Jun 2018)" );
	script_name( "Cybozu Office Multiple Vulnerabilities-01 June18" );
	script_tag( name: "summary", value: "This host is installed with Cybozu Office
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the application 'Message' when viewing an external image.

  - An input validation error in 'E-mail Details Screen' of the application 'E-mail'.

  - A browse restriction bypass error in the application 'Scheduler'.

  - An error in the application 'Message' due to a flaw in processing of an
    attached file." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose sensitive information, execute arbitrary script, bypass security
  restrictions and cause denial of service condition." );
	script_tag( name: "affected", value: "Cybozu Office versions 10.0.0 to 10.7.0." );
	script_tag( name: "solution", value: "Upgrade to Cybozu Office version 10.8.0 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN51737843/index.html" );
	script_xref( name: "URL", value: "https://office-users.cybozu.co.jp" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuOffice/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
cybVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( cybVer, "^10\\." )){
	if(version_is_less_equal( version: cybVer, test_version: "10.7.0" )){
		report = report_fixed_ver( installed_version: cybVer, fixed_version: "10.8.0", install_path: path );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

