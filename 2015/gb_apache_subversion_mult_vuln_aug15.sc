CPE = "cpe:/a:apache:subversion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805095" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-3184", "CVE-2015-3187" );
	script_bugtraq_id( 76274, 76273 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-08-18 13:39:48 +0530 (Tue, 18 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Subversion Multiple Vulnerabilities - Aug15" );
	script_tag( name: "summary", value: "This host is installed with Apache Subversion
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to:

  - The  mod_authz_svn does not properly restrict anonymous access in some
    mixed anonymous/authenticated environments when using Apache httpd 2.4.

  - The svnserve will reveal some paths  that should be hidden by path-based
    authz.  When a node is copied rom an unreadable location to a readable
    location the unreadable path may be revealed." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated remote attacker to obtain potentially sensitive information
  from an ostensibly hidden repository." );
	script_tag( name: "affected", value: "Apache Subversion 1.7.x before 1.7.21 and 1.8.x before 1.8.14" );
	script_tag( name: "solution", value: "Upgrade to version 1.7.21 or 1.8.14 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1033215" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2015-3187-advisory.txt" );
	script_xref( name: "URL", value: "http://subversion.apache.org/security/CVE-2015-3184-advisory.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_in_range( version: subver, test_version: "1.7.0", test_version2: "1.7.20" )){
	fix = "1.7.21";
	VULN = TRUE;
}
if(version_in_range( version: subver, test_version: "1.8.0", test_version2: "1.8.13" )){
	fix = "1.8.14";
	VULN = TRUE;
}
if(VULN){
	report = "Installed version: " + subver + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report, port: http_port );
	exit( 0 );
}

