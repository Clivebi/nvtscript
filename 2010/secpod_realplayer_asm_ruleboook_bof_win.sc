if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902111" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4247" );
	script_bugtraq_id( 37880 );
	script_name( "RealNetworks RealPlayer ASM RuleBook BOF Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38218" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55794" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0178" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/01192010_player/en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes within
  the context of the application and can cause heap overflow or cause remote
  code execution." );
	script_tag( name: "affected", value: "RealPlayer SP  1.0.0 and 1.0.1,
  RealPlayer versions before 10.5(6.0.12.1741) and
  RealPlayer versions 11.0.0 through 11.0.4 on Windows platforms" );
	script_tag( name: "insight", value: "The buffer overflow error occurs when processing a malformed 'ASM RuleBook'." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 10.5(6.0.12.1741) or 11.0.5 or 12.0.0.343" );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to Buffer
  Overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(version_is_less( version: rpVer, test_version: "6.0.12.1741" ) || version_in_range( version: rpVer, test_version: "11.0.0", test_version2: "11.0.0.477" ) || version_in_range( version: rpVer, test_version: "12.0.0", test_version2: "12.0.0.342" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

