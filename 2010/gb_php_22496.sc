CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100606" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)" );
	script_bugtraq_id( 22496 );
	script_cve_id( "CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910" );
	script_name( "PHP 5.2.0 and Prior Versions Multiple Vulnerabilities" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/22496" );
	script_xref( name: "URL", value: "http://support.avaya.com/elmodocs2/security/ASA-2007-136.htm" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.2.1" );
	script_xref( name: "URL", value: "http://www.php.net/releases/5_2_1.php" );
	script_xref( name: "URL", value: "http://support.avaya.com/elmodocs2/security/ASA-2007-101.htm" );
	script_xref( name: "URL", value: "http://rhn.redhat.com/errata/RHSA-2007-0076.html" );
	script_xref( name: "URL", value: "http://rhn.redhat.com/errata/RHSA-2007-0081.html#Red%20Hat%20Linux%20Advanced%20Workstation%202.1%20for%20the%20Itanium%20Processor" );
	script_xref( name: "URL", value: "http://rhn.redhat.com/errata/RHSA-2007-0082.html" );
	script_xref( name: "URL", value: "http://rhn.redhat.com/errata/RHSA-2007-0089.html" );
	script_xref( name: "URL", value: "http://www.novell.com/linux/security/advisories/2007_44_php.html" );
	script_tag( name: "affected", value: "These issues are reported to affect PHP 4.4.4 and prior versions in
  the 4 branch, and 5.2.0 and prior versions in the 5 branch. Other versions may also be vulnerable." );
	script_tag( name: "solution", value: "The vendor has released updates to address these issues. Contact the
  vendor for details on obtaining and applying the appropriate updates.

  Please see the advisories for more information." );
	script_tag( name: "summary", value: "PHP 5.2.0 and prior versions are prone to multiple security
  vulnerabilities. Successful exploits could allow an attacker to write
  files in unauthorized locations, cause a denial-of-service condition,
  and potentially execute code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "4", test_version2: "4.4.4" ) || version_in_range( version: vers, test_version: "5", test_version2: "5.2.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.4.5/5.2.1" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

