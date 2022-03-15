CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112085" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-17 12:34:56 +0200 (Tue, 17 Oct 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-02 14:06:00 +0000 (Fri, 02 Mar 2018)" );
	script_cve_id( "CVE-2016-8743", "CVE-2017-12544", "CVE-2017-12545", "CVE-2017-12546", "CVE-2017-12547", "CVE-2017-12548", "CVE-2017-12549", "CVE-2017-12550", "CVE-2017-12551", "CVE-2017-12552", "CVE-2017-12553" );
	script_bugtraq_id( 101029, 95077 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP System Management Homepage Multiple Remote Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_tag( name: "summary", value: "The host is installed with HP System
  Management Homepage and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  input validation errors, security misconfiguration and improper authentication
  mechanism." );
	script_tag( name: "impact", value: "Successfully exploiting these issue allow
  attackers to obtain sensitive information, bypass authentication, execute
  arbitrary commands, cause denial of service and local unqualified configuration
  change." );
	script_tag( name: "affected", value: "HPE System Management Homepage versions prior to v7.6.1" );
	script_tag( name: "solution", value: "Update to v7.6.1 or later" );
	script_xref( name: "URL", value: "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbmu03753en_us" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!hpport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: hpport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.6.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.6.1", install_path: path );
	security_message( port: hpport, data: report );
	exit( 0 );
}
exit( 0 );

