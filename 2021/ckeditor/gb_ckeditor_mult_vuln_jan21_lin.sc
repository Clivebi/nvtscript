CPE = "cpe:/a:ckeditor:ckeditor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145269" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-28 04:31:29 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2021-26271", "CVE-2021-26272" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CKEditor 4.0 < 4.16 Multiple ReDoS Vulnerabilities - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "sw_ckeditor_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "ckeditor/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "CKEditor is prone to multiple regular expression denial of
  service (ReDoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-26271: ReDoS in the Advanced Tab for Dialogs plugin

  - CVE-2021-26272: ReDoS in the Autolink plugin" );
	script_tag( name: "affected", value: "CKEditor version 4.0 through 4.15.1." );
	script_tag( name: "solution", value: "Update to version 4.16 or later" );
	script_xref( name: "URL", value: "https://github.com/ckeditor/ckeditor4/blob/major/CHANGES.md#ckeditor-416" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.15.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

