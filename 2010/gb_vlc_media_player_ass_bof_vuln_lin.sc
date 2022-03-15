if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800445" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0364" );
	script_bugtraq_id( 37832 );
	script_name( "VLC Media Player ASS File Buffer Overflow Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55717" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11174" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_vlc_media_player_detect_lin.sc" );
	script_mandatory_keys( "VLCPlayer/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code, and can
  cause application crash." );
	script_tag( name: "affected", value: "VLC Media Player version 0.8.6 on Linux." );
	script_tag( name: "insight", value: "The flaw exists due to stack-based buffer overflow error in Aegisub Advanced
  SubStation ('.ass') file handler that fails to perform adequate boundary
  checks on user-supplied input." );
	script_tag( name: "solution", value: "Upgrade to VLC Media Player version 1.0.5 or later" );
	script_tag( name: "summary", value: "This host is installed with VLC Media Player and is prone to
  Stack-Based Buffer Overflow Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
vlcVer = get_kb_item( "VLCPlayer/Lin/Ver" );
if(!isnull( vlcVer ) && IsMatchRegexp( vlcVer, "^0\\.8\\.6.*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

