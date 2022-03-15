CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815203" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-5439", "CVE-2019-12874" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-25 12:15:00 +0000 (Tue, 25 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-11 11:04:34 +0530 (Tue, 11 Jun 2019)" );
	script_name( "VLC Media Player Multiple Vulnerabilities Jun19 (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vlc_media_player_detect_macosx.sc" );
	script_mandatory_keys( "VLC/Media/Player/MacOSX/Version" );
	script_xref( name: "URL", value: "https://www.videolan.org/developers/vlc-branch/NEWS" );
	script_xref( name: "URL", value: "https://www.videolan.org/security/sa1901.html" );
	script_xref( name: "URL", value: "https://www.pentestpartners.com/security-blog/double-free-rce-in-vlc-a-honggfuzz-how-to/" );
	script_xref( name: "URL", value: "https://hackerone.com/reports/484398" );
	script_tag( name: "summary", value: "The host is installed with VLC media player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out of bounds write error in faad2 library.

  - Multiple out-of-band read errors.

  - Multiple heap overflow errors.

  - A NULL pointer dereference error.

  - Multiple use-after-free issues.

  - An integer underflow error.

  - Multiple integer overflow errors.

  - A division by zero error.

  - A floating point exception error.

  - An infinite loop error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code in the context of the affected application, cause
  denial of service or launch other attacks." );
	script_tag( name: "affected", value: "VideoLAN VLC media player version before 3.0.7 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 3.0.7 or later. Please see the
  references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vlcVer = infos["version"];
vlcpath = infos["location"];
if(version_is_less( version: vlcVer, test_version: "3.0.7" )){
	report = report_fixed_ver( installed_version: vlcVer, fixed_version: "3.0.7", install_path: vlcpath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

