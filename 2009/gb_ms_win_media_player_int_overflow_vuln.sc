if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800328" );
	script_version( "2020-01-07T08:11:35+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 08:11:35 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5745" );
	script_bugtraq_id( 33042 );
	script_name( "Integer Overflow vulnerability in Microsoft Windows Media Player" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_ms_win_media_player_detect_900173.sc" );
	script_mandatory_keys( "Win/MediaPlayer/Ver" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Dec/1021495.html" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/33042.c" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary codes
  and cause application crash." );
	script_tag( name: "affected", value: "Microsoft, Windows Media Player version 9.x, 10.x, and 11.x" );
	script_tag( name: "insight", value: "The issue is due to improper loading of WAV, SND or MID files on
  the affected application." );
	script_tag( name: "solution", value: "Upgrade to Windows server 2003 SP2, or later versions of
  windows, which fixes this issue." );
	script_tag( name: "summary", value: "This host has Windows Media Player installed and is prone to
  Integer Overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
if(!version = get_kb_item( "Win/MediaPlayer/Ver" )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^(9|1[01])\\..*$" )){
	security_message( port: 0 );
	exit( 0 );
}
exit( 99 );

