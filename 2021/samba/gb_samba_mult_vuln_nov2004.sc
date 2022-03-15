CPE = "cpe:/a:samba:samba";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150719" );
	script_version( "2021-09-29T04:35:02+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-09-24 10:59:30 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2004-0882", "CVE-2004-0930" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Samba 3.0.0 <= 3.0.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_nativelanman.sc", "gb_samba_detect.sc" );
	script_mandatory_keys( "samba/smb_or_ssh/detected" );
	script_tag( name: "summary", value: "Samba is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- CVE-2004-0882:

  Invalid bounds checking in reply to certain trans2 requests
  could result in a buffer overrun in smbd.  In order to exploit
  this defect, the attacker must be able to create files with very
  specific Unicode filenames on the Samba share.

  - CVE-2004-0930:

  A bug in the input validation routines used to match
  filename strings containing wildcard characters may allow
  a user to consume more than normal amounts of CPU cycles
  thus impacting the performance and response of the server.
  In some circumstances the server can become entirely
  unresponsive." );
	script_tag( name: "affected", value: "Samba versions 3.0.0 through 3.0.7." );
	script_tag( name: "solution", value: "Update to version 3.0.8 or later." );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2004-0882.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2004-0930.html" );
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
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

