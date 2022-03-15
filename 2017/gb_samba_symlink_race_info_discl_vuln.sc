CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810729" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-2619" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-04 11:09:27 +0530 (Tue, 04 Apr 2017)" );
	script_name( "Samba Server Symlink Race Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/41740/" );
	script_xref( name: "URL", value: "https://bugs.chromium.org/p/project-zero/issues/detail?id=1039" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2017-2619.html" );
	script_tag( name: "summary", value: "Samba is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The time-of-check, time-of-use race
  condition in Samba, a SMB/CIFS file, print, and login server for Unix.
  A malicious client can take advantage of this flaw by exploiting a symlink
  race to access areas of the server file system not exported under a share
  definition." );
	script_tag( name: "impact", value: "Successful exploitation will allow clients
  to access non-exported parts of the file system via symlinks." );
	script_tag( name: "affected", value: "Samba Server versions 4.6.x before 4.6.1,

  Samba Server versions 4.4.x before 4.4.12, and

  Samba Server versions 4.5.x before 4.5.7." );
	script_tag( name: "solution", value: "Upgrade to Samba 4.6.1 or 4.4.12 or 4.5.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
vers = infos["version"];
loc = infos["location"];
if( version_is_equal( version: vers, test_version: "4.6.0" ) ){
	fix = "4.6.1";
	VULN = TRUE;
}
else {
	if( version_in_range( version: vers, test_version: "4.4.0", test_version2: "4.4.11" ) ){
		fix = "4.4.11";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: vers, test_version: "4.5.0", test_version2: "4.5.6" )){
			fix = "4.5.7";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

