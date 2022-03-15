CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106697" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-28 11:42:33 +0700 (Tue, 28 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-22 12:00:00 +0000 (Thu, 22 Jun 2017)" );
	script_cve_id( "CVE-2017-7255", "CVE-2017-7256", "CVE-2017-7257", "CVE-2017-9668" );
	script_bugtraq_id( 97203, 97204, 97205 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "CMS Made Simple Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "CMS Made Simple is prone to multiple cross-site scripting vulnerabilities:

  - XSS in the 'Content-->News-->Add Article' feature via the m1_title parameter. (CVE-2017-7255)

  - XSS in the 'Content-->News-->Add Article' feature via the m1_summary parameter. (CVE-2017-7256)

  - XSS in the 'Content-->News-->Add Article' feature via the m1_content parameter. (CVE-2017-7257)

  - In admin\\addgroup.php when adding a user group, there is no XSS filtering, resulting in storage-type XSS
generation, via the description parameter in an addgroup action. (CVE-2017-9668)" );
	script_tag( name: "affected", value: "CMS Made Simple version 2.1.6." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/XiaoZhis/ProjectSend/issues/2" );
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
if(version_is_equal( version: version, test_version: "2.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

