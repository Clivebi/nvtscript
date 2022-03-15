CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117696" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-27 06:23:21 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-10-02 03:15:00 +0000 (Sat, 02 Oct 2021)" );
	script_cve_id( "CVE-2021-41617" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSH 6.2 <= 8.7 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "OpenSSH is prone to a privilege scalation vulnerability in
  certain configurations." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "sshd failed to correctly initialise supplemental groups when
  executing an AuthorizedKeysCommand or AuthorizedPrincipalsCommand, where a
  AuthorizedKeysCommandUser or AuthorizedPrincipalsCommandUser directive has been set to run the
  command as a different user. Instead these commands would inherit the groups that sshd was started
  with.

  Depending on system configuration, inherited groups may allow
  AuthorizedKeysCommand/AuthorizedPrincipalsCommand helper programs to gain unintended privilege.

  Neither AuthorizedKeysCommand nor AuthorizedPrincipalsCommand are enabled by default in
  sshd_config." );
	script_tag( name: "affected", value: "OpenSSH versions 6.2 through 8.7." );
	script_tag( name: "solution", value: "Update to version 8.8 or later." );
	script_xref( name: "URL", value: "https://www.openssh.com/txt/release-8.8" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "6.2", test_version2: "8.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

