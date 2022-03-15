if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900545" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1371", "CVE-2009-1372" );
	script_bugtraq_id( 34446 );
	script_name( "ClamAV Denial of Service Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_lin.sc" );
	script_mandatory_keys( "ClamAV/Lin/Ver" );
	script_tag( name: "impact", value: "Attackers can exploit this issue by executing arbitrary code via a crafted
  URL in the context of affected application, and can cause denial of service." );
	script_tag( name: "affected", value: "ClamAV before 0.95.1 on Linux." );
	script_tag( name: "insight", value: "- Error in CLI_ISCONTAINED macro in libclamav/others.h while processing
    malformed files packed with UPack.

  - Buffer overflow error in cli_url_canon() function in libclamav/phishcheck.c
    while handling specially crafted URLs." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.95.1." );
	script_tag( name: "summary", value: "The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34612/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0985" );
	exit( 0 );
}
require("version_func.inc.sc");
avVer = get_kb_item( "ClamAV/Lin/Ver" );
if(!avVer){
	exit( 0 );
}
if(version_is_less( version: avVer, test_version: "0.95.1" )){
	report = report_fixed_ver( installed_version: avVer, fixed_version: "0.95.1" );
	security_message( port: 0, data: report );
}

