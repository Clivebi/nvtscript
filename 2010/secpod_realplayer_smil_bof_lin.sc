if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902109" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4257" );
	script_bugtraq_id( 37880 );
	script_name( "RealNetworks RealPlayer SMIL file BOF Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38218" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55794" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0178" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/01192010_player/en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_realplayer_detect_lin.sc" );
	script_mandatory_keys( "RealPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes within
  the context of the application and can cause heap overflow or cause remote
  code execution." );
	script_tag( name: "affected", value: "RealPlayer versions 10.x and 11.0.0 on Linux platforms." );
	script_tag( name: "insight", value: "The buffer overflow error exists when processing a malformed 'SMIL file'." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 11.0.5 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to Buffer
  overflow vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Linux/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(( IsMatchRegexp( rpVer, "^10\\.*" ) ) || version_is_equal( version: rpVer, test_version: "11.0.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

