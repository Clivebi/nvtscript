CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800761" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_bugtraq_id( 39632 );
	script_cve_id( "CVE-2010-1034" );
	script_name( "HP System Management Homepage Unspecified Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "HP/SMH/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Apr/1023909.html" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02029444" );
	script_tag( name: "insight", value: "The flaw is caused by unspecified errors with unknown impacts and unknown
  attack vectors." );
	script_tag( name: "solution", value: "Upgrade to HP SMH version 6.0.0.96 (for windows)" );
	script_tag( name: "summary", value: "This host is running  HP System Management Homepage (SMH) and is
  prone to unspecified vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to access and
  modify data and cause denial of service conditions." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) 6.0 prior to 6.0.0.96" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.0.95" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.0.96" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

