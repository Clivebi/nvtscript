if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850167" );
	script_version( "$Revision: 14110 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 10:28:23 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "SUSE-SA", value: "2011-025" );
	script_cve_id( "CVE-2011-0589", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620", "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624", "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627" );
	script_name( "SuSE Update for flash-player SUSE-SA:2011:025" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.3" );
	script_tag( name: "impact", value: "remote code execution" );
	script_tag( name: "affected", value: "flash-player on openSUSE 11.3" );
	script_tag( name: "insight", value: "Flash Player has been updated to version 10.3, fixing bugs
  and security issues.
  Buffer Errors (CWE-119), Numeric Errors (CWE-189)
  Input Validation (CWE-20)

  More information can be found on the referenced vendor advisory." );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-12.html" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "openSUSE11.3"){
	if(( res = isrpmvuln( pkg: "flash-player", rpm: "flash-player~10.3.181.14~0.2.1", rls: "openSUSE11.3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

