CPE = "cpe:/o:mikrotik:routeros";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143630" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-03-24 07:19:01 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-25 14:37:00 +0000 (Tue, 25 May 2021)" );
	script_cve_id( "CVE-2020-10364" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "MikroTik RouterOS <= 6.44.3 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_mikrotik_router_routeros_consolidation.sc" );
	script_mandatory_keys( "mikrotik/detected" );
	script_tag( name: "summary", value: "MikroTik RouterOS is prone to a denial of service vulnerability in the SSH
  daemon." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SSH daemon on MikroTik routers could allow remote attackers to generate
  CPU activity, trigger refusal of new authorized connections, and cause a reboot via connect and write system
  calls, because of uncontrolled resource management." );
	script_tag( name: "affected", value: "MikroTik RouterOS version 6.44.3 and prior." );
	script_tag( name: "solution", value: "The vendor suggests the following steps to harden and tune the SSH
  daemon by using a firewall filter and service port restrictions:

  - Reduce the number of allowed unauthenticated connections.

  - Set the maximum number of concurrent connections to the SSH daemon." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/48228" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.44.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

