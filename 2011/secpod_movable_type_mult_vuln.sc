CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902402" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)" );
	script_cve_id( "CVE-2010-3921", "CVE-2010-3922", "CVE-2010-4509", "CVE-2010-4511" );
	script_bugtraq_id( 45380, 45383, 45250, 45253 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Movable Type Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42539" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3145" );
	script_xref( name: "URL", value: "http://www.movabletype.org/documentation/appendices/release-notes/movable-type-504-435-release-notes.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "movabletype/detected" );
	script_tag( name: "insight", value: "Multiple flaws are caused by input validation errors related to
  'mt:AssetProperty' and 'mt:EntryFlag' tags and in dynamic publishing error
  messages, which could be exploited to conduct SQL injection or cross site scripting attacks." );
	script_tag( name: "solution", value: "Upgrade Movable Type to 4.35 and 5.04 or later." );
	script_tag( name: "summary", value: "This host is running movable type and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain knowledge of sensitive
  information or inject SQL queries." );
	script_tag( name: "affected", value: "Movable Type version 4.x before 4.35 and 5.x before 5.04" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mtVer = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: mtVer, test_version: "4.0", test_version2: "4.34" ) || version_in_range( version: mtVer, test_version: "5.0", test_version2: "5.03" )){
	report = report_fixed_ver( installed_version: mtVer, fixed_version: "4.35 / 5.04" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

