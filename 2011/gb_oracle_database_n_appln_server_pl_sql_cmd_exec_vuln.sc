if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802525" );
	script_version( "2020-11-20T06:21:12+0000" );
	script_cve_id( "CVE-2006-0435" );
	script_bugtraq_id( 16384 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-20 06:21:12 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-12-07 12:32:19 +0530 (Wed, 07 Dec 2011)" );
	script_name( "Oracle Database Server and Application Server Multiple Unspecified Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "oracle_tnslsnr_version.sc", "gb_oracle_app_server_detect.sc" );
	script_mandatory_keys( "oracle/tnslsnr_or_application_server/detected" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/169164" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1015961" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/24363" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/423822/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/423819/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2006-090826.html" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to send a specially-crafted HTTP
  request to bypass the PLSQLExclusion list and execute SQL commands on the back-end database with DBA privileges." );
	script_tag( name: "affected", value: "Oracle Database server versions 9.2.0.7 and 10.1.0.5

  Oracle Application server versions 1.0.2.2, 9.0.4.2, 10.1.2.0.2, 10.1.2.1 and 10.1.3.0.0" );
	script_tag( name: "insight", value: "The flaw is due to error in Oracle PL/SQL Gateway, which fails to
  properly validate user-supplied HTTP requests." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is running Oracle database or application server and
  is prone to SQL command execution vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("port_service_func.inc.sc");
dbPorts = service_get_ports( proto: "oracle_tnslsnr", default_port_list: make_list( 1521 ) );
for dbPort in dbPorts {
	dbVer = get_kb_item( "oracle_tnslsnr/" + dbPort + "/version" );
	if(dbVer){
		dbVer = eregmatch( pattern: "Version ([0-9.]+)", string: dbVer );
		if(dbVer[1]){
			if(version_in_range( version: dbVer[1], test_version: "9.2.0", test_version2: "9.2.0.7" ) || version_in_range( version: dbVer[1], test_version: "10.1.0", test_version2: "10.1.0.5" )){
				report = report_fixed_ver( installed_version: dbVer[1], fixed_version: "See references" );
				security_message( port: dbPort, data: report );
				continue;
			}
		}
	}
}
CPE = "cpe:/a:oracle:application_server";
if(!appPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!appVer = get_app_version( cpe: CPE, port: appPort )){
	exit( 0 );
}
if(version_is_less( version: appVer, test_version: "1.0.2.2" ) || version_in_range( version: appVer, test_version: "9.0", test_version2: "9.0.4.2" ) || version_in_range( version: appVer, test_version: "10.1.2.0", test_version2: "10.1.3.0" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "See references" );
	security_message( port: appPort, data: report );
	exit( 0 );
}
exit( 99 );

