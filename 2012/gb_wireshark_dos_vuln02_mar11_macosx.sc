if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802902" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-1143" );
	script_bugtraq_id( 46796 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-06-27 16:05:24 +0530 (Wed, 27 Jun 2012)" );
	script_name( "Wireshark Denial of Service Vulnerability-02 March 11 (Mac OS X)" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "Wireshark version prior to 1.4.4 on Mac OS X" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'epan/dissectors/packet-ntlmssp.c' in
  the NTLMSSP dissector" );
	script_tag( name: "solution", value: "Upgrade to the Wireshark version 1.4.4" );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to multiple DoS
  vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43554" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5157" );
	script_xref( name: "URL", value: "http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html" );
	script_xref( name: "URL", value: "http://anonsvn.wireshark.org/viewvc?revision=34018&view=revision" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/MacOSX/Version" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_is_less( version: wiresharkVer, test_version: "1.4.4" )){
	report = report_fixed_ver( installed_version: wiresharkVer, fixed_version: "1.4.4" );
	security_message( port: 0, data: report );
}

