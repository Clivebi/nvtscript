if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803304" );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-01 19:35:22 +0530 (Fri, 01 Feb 2013)" );
	script_bugtraq_id( 57558 );
	script_cve_id( "CVE-2013-0107" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Foxit Advanced PDF Editor Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/275219" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2013-0107" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_foxit_advanced_pdf_editor_detect_win.sc" );
	script_mandatory_keys( "foxit/advanced_editor/win/ver" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to execute arbitrary code or
  cause a denial-of-service." );
	script_tag( name: "affected", value: "Foxit Advanced PDF Editor Version 3.x before 3.04" );
	script_tag( name: "insight", value: "The flaw caused due to stack buffer overflow, which allow attackers to
  execute arbitrary code via a crafted document containing instructions that
  reconstruct a certain security cookie." );
	script_tag( name: "solution", value: "Upgrade to the Foxit Advanced PDF Editor version 3.04 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Foxit Advanced PDF Editor and is prone
  to buffer overflow vulnerability." );
	script_xref( name: "URL", value: "http://www.foxitsoftware.com/downloads" );
	exit( 0 );
}
require("version_func.inc.sc");
foxitVer = get_kb_item( "foxit/advanced_editor/win/ver" );
if(foxitVer && IsMatchRegexp( foxitVer, "^3" )){
	if(version_is_less( version: foxitVer, test_version: "3.0.4.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

