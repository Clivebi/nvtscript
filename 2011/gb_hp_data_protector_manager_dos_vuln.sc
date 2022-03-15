CPE = "cpe:/a:hp:data_protector";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801579" );
	script_version( "2021-08-09T06:49:35+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 06:49:35 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0514" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "HP (OpenView Storage) Data Protector Manager DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "hp_data_protector_installed.sc" );
	script_mandatory_keys( "microfocus/data_protector/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause denial of
  service condition." );
	script_tag( name: "affected", value: "HP (OpenView Storage) Data Protector Manager 6.11." );
	script_tag( name: "insight", value: "The flaw is caused by an error in the RDS service (rds.exe) when
  processing malformed packets sent to port 1530/TCP, which could be exploited by remote attackers
  to crash an affected server." );
	script_tag( name: "summary", value: "HP (OpenView Storage) Data Protector Manager is prone to a
  denial of service (DoS) vulnerability." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15940/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0064" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/viewAlert.x?alertId=21937" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "06.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

