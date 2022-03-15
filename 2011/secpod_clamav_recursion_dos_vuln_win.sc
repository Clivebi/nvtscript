if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902760" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3627" );
	script_bugtraq_id( 50183 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-22 17:51:52 +0530 (Tue, 22 Nov 2011)" );
	script_name( "ClamAV Recursion Level Handling Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/USN-1258-1/" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=746984" );
	script_xref( name: "URL", value: "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=3d664817f6ef833a17414a4ecea42004c35cc42f" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_win.sc" );
	script_mandatory_keys( "ClamAV/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service
  (crash) via vectors related to recursion level." );
	script_tag( name: "affected", value: "ClamAV before 0.97.3 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to the way the bytecode engine handled recursion
  level when scanning an unpacked file." );
	script_tag( name: "solution", value: "Upgrade to ClamAV version 0.97.3 or later" );
	script_tag( name: "summary", value: "The host is installed with ClamAV and is prone to denial of service
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.clamav.net/lang/en/download/" );
	exit( 0 );
}
require("version_func.inc.sc");
avVer = get_kb_item( "ClamAV/Win/Ver" );
if(avVer == NULL){
	exit( 0 );
}
if(version_is_less( version: avVer, test_version: "0.97.3" )){
	report = report_fixed_ver( installed_version: avVer, fixed_version: "0.97.3" );
	security_message( port: 0, data: report );
}

