CPE = "cpe:/h:cisco:web_security_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106294" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-09-29 12:29:18 +0700 (Thu, 29 Sep 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2016-6416" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Web Security Appliance File Transfer Protocol Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_wsa_version.sc" );
	script_mandatory_keys( "cisco_wsa/installed" );
	script_tag( name: "summary", value: "A vulnerability in the local File Transfer Protocol (FTP) service on the
Cisco AsyncOS for Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial
of service (DoS) condition." );
	script_tag( name: "insight", value: "The vulnerability is due to lack of throttling of FTP connections. An
attacker could exploit this vulnerability by sending a flood of FTP traffic to the local FTP service on the
targeted device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition." );
	script_tag( name: "solution", value: "Upgrade to version 10.0.0-237 or later." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aos" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "9.0.0-162",
	 "9.1.0-000",
	 "9.1.0-070",
	 "9.5.0-235",
	 "9.5.0-284",
	 "9.5.0-444" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "10.0.0-237" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

