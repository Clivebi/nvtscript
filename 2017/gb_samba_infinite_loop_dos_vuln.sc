CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811083" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-9461" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-07 17:35:53 +0530 (Wed, 07 Jun 2017)" );
	script_name( "Samba 'fd_open_atomic infinite loop' Denial-of-Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_xref( name: "URL", value: "https://bugzilla.samba.org/show_bug.cgi?id=12572" );
	script_xref( name: "URL", value: "https://git.samba.org/?p=samba.git;a=commit;h=10c3e3923022485c720f322ca4f0aca5d7501310" );
	script_tag( name: "summary", value: "Samba is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in smbd
  which enters infinite loop when trying to open an invalid symlink with O_CREAT." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow
  remote attackers to conduct a denial-of-service condition(infinite loop with
  high CPU usage and memory consumption)." );
	script_tag( name: "affected", value: "Samba versions before 4.4.10 and 4.5.x
  before 4.5.6" );
	script_tag( name: "solution", value: "Upgrade to Samba 4.4.10 or 4.5.6 or later." );
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
if( version_is_less( version: vers, test_version: "4.4.10" ) ){
	fix = "4.4.10";
}
else {
	if(IsMatchRegexp( vers, "^4\\.5\\." ) && version_is_less( version: vers, test_version: "4.5.6" )){
		fix = "4.5.6";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: loc );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

