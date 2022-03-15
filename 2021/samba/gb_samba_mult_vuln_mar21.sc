CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117278" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-26 13:38:54 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)" );
	script_cve_id( "CVE-2020-27840", "CVE-2021-20277" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba 4.x Multiple DoS Vulnerabilities (Mar 2021)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple Denial of Service (DoS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The following flaws exist:

  - CVE-2020-27840: Heap corruption via crafted DN strings. An anonymous attacker can
  crash the Samba AD DC LDAP server by sending easily crafted DNs as part of a bind
  request. More serious heap corruption is likely also possible.

  - CVE-2021-20277: Out of bounds read in AD DC LDAP server. User-controlled LDAP filter
  strings against the AD DC LDAP server may crash the LDAP server." );
	script_tag( name: "affected", value: "Samba version 4.0 and later." );
	script_tag( name: "solution", value: "Update to version 4.12.12, 4.13.5, 4.14.0 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2020-27840.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2021-20277.html" );
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
if( version_in_range( version: version, test_version: "4.0", test_version2: "4.12.11" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.12.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "4.13.0", test_version2: "4.13.4" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.13.5", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

