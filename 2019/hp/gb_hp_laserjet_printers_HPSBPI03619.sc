if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142513" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-28 03:20:03 +0000 (Fri, 28 Jun 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-24 13:53:00 +0000 (Thu, 24 Oct 2019)" );
	script_cve_id( "CVE-2019-6323", "CVE-2019-6324", "CVE-2019-6325", "CVE-2019-6326", "CVE-2019-6327" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP LaserJet Pro Multiple Vulnerabilities (HPSBPI03619)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_mandatory_keys( "hp_printer/installed" );
	script_tag( name: "summary", value: "Certain HP LaserJet Pro printers are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Multiple XSS vulnerabilities (CVE-2019-6323, CVE-2019-6324)

  - A CSRF vulnerability (CVE-2019-6325)

  - Multiple buffer overflow vulnerabilities (CVE-2019-6326, CVE-2019-6327)" );
	script_tag( name: "affected", value: "HP Color LaserJet Pro M280-M281 Multifunction Printer series and
  HP LaserJet Pro MFP M28-M31 Printer series." );
	script_tag( name: "solution", value: "Update to firmware version 20190419 (LaserJet Pro M280-M281), 20190426
  (LaserJet Pro MFP M28-M31) or later." );
	script_xref( name: "URL", value: "https://support.hp.com/us-en/document/c06356322" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE_PREFIX = "cpe:/h:hp:laserjet_mfp_m";
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX )){
	exit( 0 );
}
cpe = infos["cpe"];
if(!version = get_app_version( cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
if( IsMatchRegexp( cpe, "^cpe:/h:hp:laserjet_mfp_m28[01]" ) ){
	if(version_is_less( version: version, test_version: "20190419" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "20190419" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(IsMatchRegexp( cpe, "^cpe:/h:hp:laserjet_mfp_m(28|29|30|31)[a-z]" )){
		if(version_is_less( version: version, test_version: "20190426" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "20190426" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

