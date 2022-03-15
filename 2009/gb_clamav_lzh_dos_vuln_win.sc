if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800596" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-6845" );
	script_bugtraq_id( 32752 );
	script_name( "ClamAV LZH File Unpacking Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.ivizsecurity.com/security-advisory-iviz-sr-08011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_win.sc" );
	script_mandatory_keys( "ClamAV/Win/Ver" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code in the context
  of affected application, and can cause denial of service." );
	script_tag( name: "affected", value: "ClamAV 0.93.3 and prior on Windows." );
	script_tag( name: "insight", value: "A segmentation fault ocurs in the unpack feature when processing malicious
  LZH file." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.94 or later." );
	script_tag( name: "summary", value: "The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
clamavVer = get_kb_item( "ClamAV/Win/Ver" );
if(!clamavVer){
	exit( 0 );
}
if(version_is_less_equal( version: clamavVer, test_version: "0.93.3" )){
	report = report_fixed_ver( installed_version: clamavVer, vulnerable_range: "Less than or equal to 0.93.3" );
	security_message( port: 0, data: report );
}

