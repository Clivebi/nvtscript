if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802292" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 44192 );
	script_cve_id( "CVE-2010-4053" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-01-12 17:17:17 +0530 (Thu, 12 Jan 2012)" );
	script_name( "IBM Informix Dynamic Server 'oninit.exe' Buffer Overflow Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41913" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/62619" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-216" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ibm_informix_dynamic_server_detect_win.sc" );
	script_mandatory_keys( "IBM/Informix/Dynamic/Server/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges." );
	script_tag( name: "affected", value: "IBM Informix Dynamic Server (IDS) 11.10 before 11.10.xC2W2 and 11.50 before 11.50.xC1" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within the logging function in
  oninit.exe and can be exploited to cause a stack-based buffer overflow by
  sending a specially crafted request to TCP ports 9088 or 1526." );
	script_tag( name: "solution", value: "Upgrade to IBM Informix IDS version 11.50.xC1, 11.10.xC2W2 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Informix Dynamic Server and is
  prone to buffer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "IBM/Informix/Dynamic/Server/Win/Ver" );
if(version){
	if(version_is_equal( version: version, test_version: "11.10" ) || version_is_equal( version: version, test_version: "11.50" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

