if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801788" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)" );
	script_cve_id( "CVE-2011-1824" );
	script_bugtraq_id( 47764 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Opera Browser 'SELECT' HTML Tag Remote Memory Corruption Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/67338" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/517914/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to trigger an invalid
  memory write operation, and consequently cause a denial of service or possibly
  execute arbitrary code." );
	script_tag( name: "affected", value: "Opera Web Browser Version before 10.61 on windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'VEGAOpBitmap::AddLine' function, which
  fails to properly initialize memory during processing of the SIZE attribute of
  a SELECT element." );
	script_tag( name: "solution", value: "Upgrade to Opera Web Browser Version 10.61 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera browser and is prone to memory
  corruption vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(operaVer){
	if(version_is_less( version: operaVer, test_version: "10.61" )){
		report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.61" );
		security_message( port: 0, data: report );
	}
}

