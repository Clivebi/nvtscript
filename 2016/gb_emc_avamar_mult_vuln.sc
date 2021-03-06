CPE = "cpe:/a:emc:avamar";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106289" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-27 11:26:32 +0700 (Tue, 27 Sep 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-0903", "CVE-2016-0904", "CVE-2016-0905", "CVE-2016-0920", "CVE-2016-0921" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "EMC Avamar Data Store and Avamar Virtual Edition Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_emc_avamar_detect.sc" );
	script_mandatory_keys( "emc_avamar/installed" );
	script_tag( name: "summary", value: "EMC Avamar Data Store and Avamar Virtual Edition are prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "EMC Avamar is prone to multiple vulnerabilities:

  - Improper client side authentication (CVE-2016-0903).

  - Improper encryption of communication channel (CVE-2016-0904).

  - Privilege escalation via sudo (CVE-2016-0905).

  - Command Injection in sudo script (CVE-2016-0920).

  - Privilege escalation due to weak file permissions (CVE-2016-0921)." );
	script_tag( name: "impact", value: "An attacker may obtain root privileges, obtain sensitive client-server
traffic information or read backup data." );
	script_tag( name: "affected", value: "EMC Avamar Data Store (ADS) and Avamar Virtual Edition (AVE) versions
prior to 7.3.0" );
	script_tag( name: "solution", value: "Update to 7.3.0-233 or later." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Sep/att-31/ESA-2016-065.txt" );
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
s = split( buffer: version, sep: ".", keep: FALSE );
if( max_index( s ) == 3 ) {
	check = "7.3.0";
}
else {
	if( max_index( s ) == 4 ) {
		check = "7.3.0.233";
	}
	else {
		exit( 0 );
	}
}
if(version_is_less( version: version, test_version: check )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.0-233" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

