if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800377" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1169" );
	script_bugtraq_id( 34235 );
	script_name( "Firefox XSL Parsing Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34471" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8285" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Mar/1021941.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-12.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause remote code execution
  through a specially crafted malicious XSL file or can cause application
  termination at runtime." );
	script_tag( name: "affected", value: "Firefox version 3.0 to 3.0.7 on Linux." );
	script_tag( name: "insight", value: "This flaw is due to improper handling of errors encountered when transforming
  an XML document which can be exploited to cause memory corrpution through a
  specially crafted XSLT code." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.0.8." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to XSL File Parsing Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Linux/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.7" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.0 - 3.0.7" );
	security_message( port: 0, data: report );
}

