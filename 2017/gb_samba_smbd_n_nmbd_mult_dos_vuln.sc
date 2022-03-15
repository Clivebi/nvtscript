CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811219" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2014-0244", "CVE-2014-3493" );
	script_bugtraq_id( 68148, 68150 );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-22 12:27:14 +0530 (Thu, 22 Jun 2017)" );
	script_name( "Samba 'smbd and nmbd' Multiple Denial-of-Service Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1030455" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2014-3493" );
	script_xref( name: "URL", value: "http://www.samba.org/samba/security/CVE-2014-0244" );
	script_tag( name: "summary", value: "Samba is prone to multiple denial-of-service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the nmbd NetBIOS name services daemon which causes the nmbd server
    to loop the CPU.

  - A memory corruption error. A valid unicode path names stored on disk can cause
    smbd to crash if an authenticated client attempts to read them using a
    non-unicode request." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow
  remote attackers to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Samba Server versions 3.6.x before 3.6.24,
  4.0.x before 4.0.19, and 4.1.x before 4.1.9." );
	script_tag( name: "solution", value: "Upgrade to Samba 3.6.24 or 4.0.19 or 4.1.9
  or later." );
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
if( IsMatchRegexp( vers, "^3\\.6\\." ) ){
	if(version_is_less( version: vers, test_version: "3.6.24" )){
		fix = "3.6.24";
	}
}
else {
	if(IsMatchRegexp( vers, "^4\\.[01]" )){
		if( version_is_less( version: vers, test_version: "4.0.19" ) ){
			fix = "4.0.19";
		}
		else {
			if(version_in_range( version: vers, test_version: "4.1", test_version2: "4.1.8" )){
				fix = "4.1.9";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

