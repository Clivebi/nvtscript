CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118173" );
	script_version( "2021-09-30T11:01:28+0000" );
	script_cve_id( "CVE-2021-30480", "CVE-2021-34407" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-30 11:01:28 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-22 20:40:00 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-08-25 16:08:43 +0200 (Wed, 25 Aug 2021)" );
	script_name( "Zoom Client Heap Based Buffer Overflow (ZSB-22003)" );
	script_tag( name: "summary", value: "Zoom Client is prone to a heap based buffer overflow
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability allows remote attackers to execute arbitrary
  code on affected installations of Zoom Clients. Authentication is not required to exploit this
  vulnerability.

  The specific flaw exists within the processing of encrypted messages. The issue results from the
  lack of proper validation of the length of user-supplied data prior to copying it to a
  fixed-length heap-based buffer. An attacker can leverage this vulnerability to execute code in the
  context of the current user." );
	script_tag( name: "affected", value: "All desktop versions of the Zoom Client for Meetings before
  5.6.3." );
	script_tag( name: "solution", value: "Update to version 5.6.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_zoom_client_detect_macosx.sc", "gb_zoom_client_detect_win.sc" );
	script_mandatory_keys( "zoom/client/detected" );
	script_xref( name: "URL", value: "https://www.zerodayinitiative.com/advisories/ZDI-21-971" );
	script_xref( name: "URL", value: "https://explore.zoom.us/en/trust/security/security-bulletin" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.6.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.6.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

