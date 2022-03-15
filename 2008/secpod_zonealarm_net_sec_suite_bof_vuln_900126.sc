if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900126" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)" );
	script_cve_id( "CVE-2008-7009" );
	script_bugtraq_id( 31124 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Buffer overflow" );
	script_name( "ZoneAlarm Internet Security Suite Buffer Overflow Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31832/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/496226" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2556" );
	script_tag( name: "summary", value: "The host has ZoneAlarm Internet Security Suite installed, which
 is prone to buffer overflow vulnerability." );
	script_tag( name: "insight", value: "The vulnerability is due to inadequate boundary checks on
        user-supplied input in multiscan.exe file when performing virus scans
        on long paths or file names. This can be exploited by tricking into
        scanning malicious directory or file names." );
	script_tag( name: "affected", value: "ZoneAlarm Internet Security Suite 8.x and prior on Windows (All)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to ZoneAlarm Internet Security Suite 9 or later." );
	script_tag( name: "impact", value: "Exploitation could allow attackers to execute arbitrary code
        on the affected system or cause denial of service." );
	script_xref( name: "URL", value: "http://www.zonealarm.com/store/content/dotzone/freeDownloads.jsp" );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
zoneVer = registry_get_sz( key: "SOFTWARE\\Zone Labs\\ZoneAlarm", item: "CurrentVersion" );
if(egrep( pattern: "^([0-6]\\..*|7\\.0(\\.[0-3]?[0-9]?[0-9]|\\.4[0-7]?[0-9]|" + "\\.48[0-3])?|8\\.0(\\.0?[01]?[0-9]|\\.020)?)(\\.0{1,3})?$", string: zoneVer )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

