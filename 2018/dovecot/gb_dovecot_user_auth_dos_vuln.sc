if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113215" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-26 14:11:32 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-2669" );
	script_name( "Dovecot User Authentication Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to a Denial of Service vulnerability within the user authentication." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When 'dict' passdb and userdb were used for user authentication, the username sent by
  the IMAP/POP3 client is sent through var_expand() to perform %variable expansion.
  Sending specially crafed %variable fields can result in excessive memory usage
  causing the process to crash (and restart), or excessive CPU usage
  causing all authentications to hang." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to temporarily deny
  every user to access the application." );
	script_tag( name: "affected", value: "Dovecot versions 2.2.26 through 2.2.28." );
	script_tag( name: "solution", value: "Update to version 2.2.29." );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2017/04/11/1" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2017-2669" );
	exit( 0 );
}
CPE = "cpe:/a:dovecot:dovecot";
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
if(version_in_range( version: version, test_version: "2.2.26", test_version2: "2.2.28" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.29", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

