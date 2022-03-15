if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102051" );
	script_version( "2020-04-24T07:24:50+0000" );
	script_tag( name: "last_modification", value: "2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)" );
	script_cve_id( "CVE-2007-1281" );
	script_bugtraq_id( 22795 );
	script_name( "Kaspersky Antivirus UPX Denial of Service vulnerability" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_kaspersky_av_detect.sc" );
	script_mandatory_keys( "Kaspersky/AV/Ver" );
	script_tag( name: "solution", value: "Update to a newer version (automatic update will do)." );
	script_tag( name: "summary", value: "Kaspersky AntiVirus Engine 6.0.1.411 for Windows allows remote
  attackers to cause a denial of service (CPU consumption) via a
  crafted UPX compressed file with a negative offset, which triggers
  an infinite loop during decompression." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "Kaspersky/AV/Ver" );
if(!version){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.0.1.411" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less or equal to 6.0.1.411" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

