if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803901" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1868", "CVE-2012-5855" );
	script_bugtraq_id( 57079, 56405 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-16 14:45:11 +0530 (Tue, 16 Jul 2013)" );
	script_name( "VLC Media Player Multiple Vulnerabilities - July 13 (MAC OS X)" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to overflow buffer, cause denial
of service or potentially execution of arbitrary code." );
	script_tag( name: "affected", value: "VLC media player version 2.0.4 and prior on MAC OS X" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Error in 'SHAddToRecentDocs()' function.

  - Error due to improper validation of user supplied inputs when handling
   HTML subtitle files." );
	script_tag( name: "solution", value: "Upgrade to VLC media player version 2.0.5 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79823" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vlc_media_player_detect_macosx.sc" );
	script_mandatory_keys( "VLC/Media/Player/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
vlcVer = get_kb_item( "VLC/Media/Player/MacOSX/Version" );
if(!vlcVer){
	exit( 0 );
}
if(version_is_less_equal( version: vlcVer, test_version: "2.0.4" )){
	report = report_fixed_ver( installed_version: vlcVer, vulnerable_range: "Less than or equal to 2.0.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}

