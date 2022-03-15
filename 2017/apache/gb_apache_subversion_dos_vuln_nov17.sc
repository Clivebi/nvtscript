CPE = "cpe:/a:apache:subversion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811983" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2013-4246" );
	script_bugtraq_id( 101620 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-18 17:45:00 +0000 (Sat, 18 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-08 18:27:59 +0530 (Wed, 08 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Subversion Denial of Service Vulnerability - Nov17" );
	script_tag( name: "summary", value: "This host is installed with Apache Subversion
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a failure to handle
  exceptional conditions." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause a denial-of-service condition." );
	script_tag( name: "affected", value: "Apache Subversion 1.8.x before 1.8.2." );
	script_tag( name: "solution", value: "Upgrade to version 1.8.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://subversion.apache.org/security/CVE-2013-4246-advisory.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_subversion_remote_detect.sc" );
	script_mandatory_keys( "Subversion/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: http_port, exit_no_version: TRUE )){
	exit( 0 );
}
subver = infos["version"];
subPath = infos["location"];
if(IsMatchRegexp( subver, "^(1\\.8)" ) && version_is_less( version: subver, test_version: "1.8.2" )){
	report = report_fixed_ver( installed_version: subver, fixed_version: "1.8.2", install_path: subPath );
	security_message( data: report, port: http_port );
	exit( 0 );
}
exit( 0 );

