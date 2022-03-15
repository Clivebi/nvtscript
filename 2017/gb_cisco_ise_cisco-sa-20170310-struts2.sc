CPE = "cpe:/a:cisco:identity_services_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106640" );
	script_cve_id( "CVE-2017-5638" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_name( "Cisco Identity Services Engine Apache Struts2 Jakarta Multipart Parser File Upload Code Execution Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "summary", value: "Cisco ISE is prone to a vulnerability in Apache Struts2." );
	script_tag( name: "insight", value: "On March 6, 2017, Apache disclosed a vulnerability in the Jakarta multipart
parser used in Apache Struts2 that could allow an attacker to execute commands remotely on the targeted system
using a crafted Content-Type header value." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-13 11:35:28 +0700 (Mon, 13 Mar 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ise_version.sc" );
	script_mandatory_keys( "cisco_ise/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
affected = make_list( "1.3.0.876",
	 "1.4.0.253",
	 "2.0.0.306",
	 "2.2.0.470",
	 "2.0.1.130",
	 "2.1.0.474",
	 "2.2.0.471" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

