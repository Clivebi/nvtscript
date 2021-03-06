if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900410" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)" );
	script_cve_id( "CVE-2008-7079" );
	script_bugtraq_id( 32446 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "Denial of Service" );
	script_name( "Nero ShowTime 'm3u' File Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7207" );
	script_xref( name: "URL", value: "http://secunia.com/Advisories/32850" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application." );
	script_tag( name: "affected", value: "Nero ShowTime 5.0.15.0 and prior on all Windows platforms." );
	script_tag( name: "insight", value: "This error is due to inadequate boundary checks on user supplied input." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Nero Showtime and is prone to
  'm3u' File Remote Buffer Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
neroExe = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\ShowTime.exe", item: "Path" );
if(neroExe){
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: neroExe );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: neroExe );
	showtime = file + "ShowTime.exe";
	showtime = GetVer( file: showtime, share: share );
	{
		pattern = "^([0-4]\\..*|5\\.0(\\.[0-9](\\..*)?|\\.1[0-4](\\..*)?|\\.15(\\.0)?)?)";
		if(egrep( pattern: pattern, string: showtime )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

