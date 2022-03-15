if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902108" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0375", "CVE-2009-0376", "CVE-2009-4241", "CVE-2009-4242", "CVE-2009-4243", "CVE-2009-4244", "CVE-2009-4245", "CVE-2009-4246", "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257" );
	script_bugtraq_id( 33652, 37880 );
	script_name( "RealNetworks RealPlayer Multiple Code Execution Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38218" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55794" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0178" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/01192010_player/en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_realplayer_detect_lin.sc" );
	script_mandatory_keys( "RealPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary
  code within the context of the application and can cause a heap overflow
  or allow remote code execution." );
	script_tag( name: "affected", value: "RealPlayer versions 10.x and prior Linux platforms." );
	script_tag( name: "insight", value: "Buffer overflow errors exist, when processing a malformed 'ASM Rulebook',
  'GIF file', 'media file', 'IVR file', 'SIPR Codec', 'SMIL file', 'Skin',
  and 'set_parameter' method." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer version 11.0.5 or later." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to multiple code
  execution vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
rpVer = get_kb_item( "RealPlayer/Linux/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(IsMatchRegexp( rpVer, "^10\\.*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

