CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803809" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2013-1022", "CVE-2013-1021", "CVE-2013-1020", "CVE-2013-1019", "CVE-2013-1018", "CVE-2013-1017", "CVE-2013-1016", "CVE-2013-1015", "CVE-2013-0989", "CVE-2013-0988", "CVE-2013-0987", "CVE-2013-0986" );
	script_bugtraq_id( 60104, 60103, 60108, 60102, 60098, 60097, 60092, 60110, 60101, 60100, 60109, 60099 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-06-07 18:15:48 +0530 (Fri, 07 Jun 2013)" );
	script_name( "Apple QuickTime Multiple Vulnerabilities - June13 (Windows)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5770" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53520" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2013/May/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption or buffer overflow." );
	script_tag( name: "affected", value: "QuickTime Player version prior to 7.7.4 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws due to boundary errors when handling:

  - FPX files

  - 'enof' and 'mvhd' atoms

  - H.263 and H.264 encoded movie files

  - A certain value in a dref atom within a MOV file

  - A channel_mode value of MP3 files within the CoreAudioToolbox component

  - Unspecified error when handling TeXML files, JPEG encoded data, QTIF files" );
	script_tag( name: "solution", value: "Upgrade to version 7.7.4 or later." );
	script_tag( name: "summary", value: "This host is installed with QuickTime Player and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.7.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.7.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

