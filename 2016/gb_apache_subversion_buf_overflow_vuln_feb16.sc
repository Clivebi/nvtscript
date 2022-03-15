CPE = "cpe:/a:apache:subversion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806851" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2015-5259" );
	script_bugtraq_id( 82300 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-02-04 17:06:21 +0530 (Thu, 04 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Subversion Buffer Overflow Vulnerability -01 Feb16" );
	script_tag( name: "summary", value: "This host is installed with Apache Subversion
  and is prone to Buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to

  - an integer overflow in the svn:// protocol parser." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to cause a denial of service or possibly execute arbitrary code under
  the context of the targeted process." );
	script_tag( name: "affected", value: "Subversion 1.9.x before 1.9.3." );
	script_tag( name: "solution", value: "Upgrade to version 1.9.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1034469" );
	script_xref( name: "URL", value: "https://subversion.apache.org/security/CVE-2015-5259-advisory.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_subversion_remote_detect.sc" );
	script_mandatory_keys( "Subversion/installed" );
	script_require_ports( "Services/www", 3690 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!subver = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(IsMatchRegexp( subver, "^(1\\.9)" )){
	if(version_is_less( version: subver, test_version: "1.9.3" )){
		report = report_fixed_ver( installed_version: subver, fixed_version: "1.9.3" );
		security_message( data: report, port: http_port );
		exit( 0 );
	}
}

