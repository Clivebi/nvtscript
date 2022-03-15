CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804323" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-1684" );
	script_bugtraq_id( 65399 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-03-06 12:15:27 +0530 (Thu, 06 Mar 2014)" );
	script_name( "VLC Media Player ASF Demuxer Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to denial of
service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a divide-by-zero error when processing malicious
'.asf' files." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service
condition." );
	script_tag( name: "affected", value: "VLC media player version 2.1.2 and prior on Windows." );
	script_tag( name: "solution", value: "Upgrade to VLC media player version 2.1.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/90955" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31429" );
	script_xref( name: "URL", value: "http://www.videolan.org/developers/vlc-branch/NEWS" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125080/VLC-Media-Player-2.1.2-Denial-Of-Service.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
vlcVer = get_app_version( cpe: CPE );
if(!vlcVer){
	exit( 0 );
}
if(version_is_less_equal( version: vlcVer, test_version: "2.1.2" )){
	report = report_fixed_ver( installed_version: vlcVer, vulnerable_range: "Less than or equal to 2.1.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}

