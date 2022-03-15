if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850292" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-08-02 23:36:37 +0530 (Thu, 02 Aug 2012)" );
	script_cve_id( "CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0755", "CVE-2012-0756", "CVE-2012-0767" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "openSUSE-SU", value: "2012:0265-1" );
	script_name( "openSUSE: Security Advisory for flash-player (openSUSE-SU-2012:0265-1)" );
	script_xref( name: "URL", value: "https://www.adobe.com/support/security/bulletins/apsb12-03.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	script_tag( name: "affected", value: "flash-player on openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "insight", value: "flash-player was updated to the security update to
  11.1.102.62.

  It fixes lots of security issues, some already exploited in
  the wild.

  Details can be found at the linked vendor advisory.

  These vulnerabilities could cause a crash and potentially
  allow an attacker to take control of the affected system.
  This update also resolves a universal cross-site scripting
  vulnerability that could be used to take actions on a
  user's behalf on any website or webmail provider, if the
  user visits a malicious website. There are reports that
  this vulnerability (CVE-2012-0767) is being exploited in
  the wild in active targeted attacks designed to trick the
  user into clicking on a malicious link delivered in an
  email message (Internet Explorer on Windows only)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
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
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "flash-player", rpm: "flash-player~11.1.102.62~0.7.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

