CPE = "cpe:/a:opmantek:nmis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106244" );
	script_version( "$Revision: 12363 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-15 09:47:18 +0700 (Thu, 15 Sep 2016)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2016-5642" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Opmantek NMIS XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opmantek_nmis_detect.sc" );
	script_mandatory_keys( "opmantek_nmis/installed" );
	script_tag( name: "summary", value: "Opmantek NMIS is prone to a cross-site scripting vulnerability via SNMP
Trap messages." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A stored server XSS vulnerability exists due to insufficient filtering
of SNMP trap supplies data before the affected software stores and displays the data." );
	script_tag( name: "impact", value: "A successful exploit could allow an attacker to execute arbitrary script
code in the context of the interface." );
	script_tag( name: "affected", value: "NMIS version 8.x." );
	script_tag( name: "solution", value: "Update to 8.5.12G or later" );
	script_xref( name: "URL", value: "https://community.rapid7.com/community/infosec/blog/2016/09/07/multiple-disclosures-for-multiple-network-management-systems-part-2" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\." )){
	if(revcomp( a: version, b: "8.5.12g" ) < 0){
		report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "8.5.12G" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

