if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900216" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 31058 );
	script_cve_id( "CVE-2008-2154", "CVE-2008-3958", "CVE-2008-3960" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_name( "IBM Db2 Universal Database Multiple Vulnerabilities - Sept08 (Linux)" );
	script_dependencies( "gb_ibm_db2_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "ibm/db2/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "ftp://ftp.software.ibm.com/ps/products/db2/fixes/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2517" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Sep/1020826.html" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1JR29274" );
	script_tag( name: "summary", value: "IBM Db2 is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The flaws exist due to unspecified errors in processing of

  - CONNECT/ATTACH requests

  - DB2FMP process and DB2JDS service" );
	script_tag( name: "affected", value: "IBM Db2 version 8 prior to Fixpak 17 on Linux (All)." );
	script_tag( name: "solution", value: "Update to version 8 Fixpak 17 or later." );
	script_tag( name: "impact", value: "Remote exploitation could allow attackers to bypass security
  restrictions, cause a denial of service or gain elevated privileges." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/a:ibm:db2";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.2.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.2.17" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

