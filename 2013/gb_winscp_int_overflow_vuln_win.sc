CPE = "cpe:/a:winscp:winscp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803873" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-4852" );
	script_bugtraq_id( 61599 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-08-21 13:50:22 +0530 (Wed, 21 Aug 2013)" );
	script_name( "WinSCP Integer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with WinSCP and is prone to integer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 5.1.6 or later." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of message lengths in the getstring()
function in sshrsa.c and sshdss.c when handling negative SSH handshake." );
	script_tag( name: "affected", value: "WinSCP version before 5.1.6 on Windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause heap-based buffer
overflows, resulting in a denial of service or potentially allowing the
execution of arbitrary code." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54355" );
	script_xref( name: "URL", value: "http://winscp.net/eng/docs/history#5.1.6" );
	script_xref( name: "URL", value: "http://winscp.net/tracker/show_bug.cgi?id=1017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_winscp_detect_win.sc" );
	script_mandatory_keys( "WinSCP/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!scpVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: scpVer, test_version: "5.1.6" )){
	report = report_fixed_ver( installed_version: scpVer, fixed_version: "5.1.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}

