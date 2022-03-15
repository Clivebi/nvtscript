CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813575" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2018-11529" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-21 20:10:00 +0000 (Thu, 21 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-07-17 11:51:09 +0530 (Tue, 17 Jul 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VLC Media Player MKV Files Arbitrary Code Execution Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper sanitization
  used by VLC media player against MKV files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code in the context of the logged-in user and failed
  exploit attempts will likely result in denial of service conditions." );
	script_tag( name: "affected", value: "VideoLAN VLC media player versions through
  2.2.8 on Mac OS X" );
	script_tag( name: "solution", value: "Update to version 3.0.3 or above. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Jul/28" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vlc_media_player_detect_macosx.sc" );
	script_mandatory_keys( "VLC/Media/Player/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vlcVer = infos["version"];
vlcpath = infos["location"];
if(version_is_less_equal( version: vlcVer, test_version: "2.2.8" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "3.0.3", install_path: vlcpath );
	security_message( data: report );
	exit( 0 );
}

