CPE = "cpe:/a:avast:antivirus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900985" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4049" );
	script_bugtraq_id( 37031 );
	script_name( "avast! 'aswRdr.sys' Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_avast_av_detect_win.sc" );
	script_mandatory_keys( "avast/antivirus/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/507891/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a Denial of
  Service or potentially gain escalated privileges." );
	script_tag( name: "affected", value: "avast! Home and Professional version 4.8.1356 and prior on Windows." );
	script_tag( name: "insight", value: "The vulnerability is due to an error in 'aswRdr.sys' when processing
  IOCTLs. This can be exploited to corrupt kernel memory via a specially crafted 0x80002024 IOCTL." );
	script_tag( name: "solution", value: "Upgrade to avast! Home and Professional version 4.8.1367 or later." );
	script_tag( name: "summary", value: "This host is installed with avast! AntiVirus and is prone to Buffer
  Overflow vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "4.8.1367" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.1367", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

