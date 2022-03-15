CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801449" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_cve_id( "CVE-2010-2802", "CVE-2009-2802" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-12 21:33:00 +0000 (Tue, 12 Nov 2019)" );
	script_name( "MantisBT < 1.2.2 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/blog/?p=113" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/08/03/7" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/08/02/16" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=11952" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_tag( name: "insight", value: "The following flaws exist:

  - the application allows remote authenticated users to inject arbitrary web script or HTML via an
  HTML document with a '.gif' filename extension, related to inline attachments (CVE-2010-2802)

  - insecure handling of attachments and MIME types (CVE-2009-2802)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.2 or later" );
	script_tag( name: "summary", value: "This host is running MantisBT and is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct cross-site scripting,
  cross-domain scripting or other browser attacks." );
	script_tag( name: "affected", value: "MantisBT version prior to version 1.2.2." );
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
if(version_is_less( version: version, test_version: "1.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

