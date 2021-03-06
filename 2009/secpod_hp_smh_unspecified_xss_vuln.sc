CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900658" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 35031 );
	script_cve_id( "CVE-2009-1418" );
	script_name( "HP System Management Homepage Unspecified XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50633" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2009/JVNDB-2009-000029.html" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01745065" );
	script_tag( name: "insight", value: "HP System Management Homepage application fails to validate user supplied
  input." );
	script_tag( name: "solution", value: "Upgrade to version 3.0.1.73 or later." );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to steal cookie-based
  authentication credentials and execute arbitrary script on the user's
  web browser by injecting web script or HTML vi remote vectors." );
	script_tag( name: "affected", value: "HP System Management Homepage versions prior to 3.0.1.73 on all platforms." );
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
if(version_is_less( version: version, test_version: "3.0.1.73" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.1.73" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

