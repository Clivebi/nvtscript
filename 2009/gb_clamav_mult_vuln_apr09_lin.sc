if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800554" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-1241", "CVE-2009-1270", "CVE-2008-6680" );
	script_bugtraq_id( 34344, 34357 );
	script_name( "ClamAV Multiple Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0934" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/04/07/6" );
	script_xref( name: "URL", value: "http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_lin.sc" );
	script_mandatory_keys( "ClamAV/Lin/Ver" );
	script_tag( name: "impact", value: "Remote attackers may exploit this issue to inject malicious files into the
  system which can bypass the scan engine and may cause denial of service." );
	script_tag( name: "affected", value: "ClamAV before 0.95 on Linux" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Error in handling specially crafted RAR files which prevents the scanning
    of potentially malicious files.

  - Inadequate sanitation of files through a crafted TAR file causes clamd and
    clamscan to hang.

  - 'libclamav/pe.c' allows remote attackers to cause a denial of service
    via a crafted EXE which triggers a divide-by-zero error." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.95." );
	script_tag( name: "summary", value: "This host has ClamAV installed and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
avVer = get_kb_item( "ClamAV/Lin/Ver" );
if(!avVer){
	exit( 0 );
}
if(version_is_less( version: avVer, test_version: "0.95" )){
	report = report_fixed_ver( installed_version: avVer, fixed_version: "0.95" );
	security_message( port: 0, data: report );
}

