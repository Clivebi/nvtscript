CPE = "cpe:/a:apache:subversion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806856" );
	script_version( "$Revision: 12096 $" );
	script_cve_id( "CVE-2013-4505" );
	script_bugtraq_id( 63966 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-08 18:19:08 +0530 (Mon, 08 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Subversion Denial Of Service Vulnerability -01 Feb16" );
	script_tag( name: "summary", value: "This host is installed with Apache Subversion
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the 'is_this_legal()'
  function in mod_dontdothat does not restrict requests from serf based
  clients." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to cause a denial of service or bypass intended access restriction." );
	script_tag( name: "affected", value: "Apache Subversion 1.4.0 through
  1.7.13 and 1.8.0 through 1.8.4" );
	script_tag( name: "solution", value: "Upgrade to version 1.7.14, or 1.8.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://subversion.apache.org/security/CVE-2013-4505-advisory.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
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
if( IsMatchRegexp( subver, "^(1\\.8)" ) ){
	if(version_is_less( version: subver, test_version: "1.8.5" )){
		report = report_fixed_ver( installed_version: subver, fixed_version: "1.8.5" );
		security_message( data: report, port: http_port );
		exit( 0 );
	}
}
else {
	if(version_in_range( version: subver, test_version: "1.4.0", test_version2: "1.7.13" )){
		report = report_fixed_ver( installed_version: subver, fixed_version: "1.7.14" );
		security_message( data: report, port: http_port );
		exit( 0 );
	}
}

