CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141732" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-29 10:17:12 +0700 (Thu, 29 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2018-14629", "CVE-2018-16851" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba 4.x Multiple DoS Vulnerabilities (CVE-2018-14629, CVE-2018-16851)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple denial of service (DoS)
  vulnerabilities." );
	script_tag( name: "insight", value: "Samba is prone to multiple vulnerabilities:

  - CVE-2018-14629: CNAME loops can cause DNS server crashes, and CNAMEs can be added by
  unprivileged users.

  - CVE-2018-16851: A user able to read more than 256MB of LDAP entries can crash the Samba AD DC's
  LDAP server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Samba version 4.x.x." );
	script_tag( name: "solution", value: "Update to version 4.7.12, 4.8.7, 4.9.3 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2018-14629.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2018-16851.html" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.7.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.12", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.8.0", test_version2: "4.8.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.7", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.9.0", test_version2: "4.9.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.9.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

