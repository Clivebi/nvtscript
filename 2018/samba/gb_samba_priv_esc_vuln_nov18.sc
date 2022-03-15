if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113287" );
	script_version( "2021-10-06T08:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2018-11-06 13:53:47 +0200 (Tue, 06 Nov 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:17:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-2126", "CVE-2016-2123" );
	script_bugtraq_id( 94994 );
	script_name( "Samba >= 4.0.0, <= 4.5.2 Multiple Privilege Escalation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple privilege escalation vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- CVE-2016-2126: Samba is prone to privilege elevation due to
  incorrect handling of the PAC (Privilege Attribute Certificate) checksum. A remote, authenticated,
  attacker can cause the winbindd process to creash using a legitimate Kerberos ticket. A local
  service with access to the winbindd privileged pipe can cause winbindd to cache elevated access
  permissions.

  - CVE-2016-2123: The Samba routine ndr_pull_dnsp_name contains an integer wrap problem, leading to
  an attacker-controlled memory overwrite. ndr_pull_dnsp_name parses data from the Samba Active
  Directory ldb database. Any user who can write to the dnsRecord attribute over LDAP can trigger this
  memory corruption.

  By default, all authenticated LDAP users can write to the dnsRecord attribute on new DNS objects.
  This makes the defect a remote privilege escalation." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  gain additional access rights." );
	script_tag( name: "affected", value: "Samba versions 4.0.0 through 4.3.12, 4.4.0 through 4.4.7 and
  4.5.0 through 4.5.2." );
	script_tag( name: "solution", value: "Update to version 4.3.13, 4.4.8 or 4.5.3 respectively." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2016-2126.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2016-2123.html" );
	exit( 0 );
}
CPE = "cpe:/a:samba:samba";
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
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.13", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.4.0", test_version2: "4.4.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.8", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5.0", test_version2: "4.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.3", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

