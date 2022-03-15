CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150748" );
	script_version( "2021-09-30T11:59:38+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-24 10:59:30 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-30 00:00:00 +0000 (Fri, 30 Dec 2016)" );
	script_cve_id( "CVE-2015-5296", "CVE-2015-5299" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba 3.2.0 <= 4.3.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple Vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- CVE-2015-5296:

  Requesting encryption should also request signing when setting up the connection to protect
  against man-in-the-middle attacks.

  - CVE-2015-5299:

  A missing access control check in the VFS shadow_copy2 module could allow unauthorized users to
  access snapshots." );
	script_tag( name: "affected", value: "Samba versions 3.2.0 through 4.1.21, 4.2.0 through 4.2.6 and
  4.3.0 through 4.3.2." );
	script_tag( name: "solution", value: "Update to version 4.1.22, 4.2.7, 4.3.3 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2015-5296.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2015-5299.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "4.1.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.22", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.0", test_version2: "4.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

