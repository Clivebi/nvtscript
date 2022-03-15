CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100470" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)" );
	script_cve_id( "CVE-2010-0442" );
	script_bugtraq_id( 37973 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "PostgreSQL 'bitsubstr' Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc" );
	script_mandatory_keys( "postgresql/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37973" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55902" );
	script_xref( name: "URL", value: "http://intevydis.blogspot.com/2010/01/postgresql-8023-bitsubstr-overflow.html" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a buffer-overflow vulnerability because the
  application fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code with
  elevated privileges or crash the affected application." );
	script_tag( name: "affected", value: "PostgreSQL version 8.0.x, 8.1.x, 8.3.x is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(version_in_range( version: vers, test_version: "8.0", test_version2: "8.0.23" ) || version_in_range( version: vers, test_version: "8.1", test_version2: "8.1.11" ) || version_in_range( version: vers, test_version: "8.3", test_version2: "8.3.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

