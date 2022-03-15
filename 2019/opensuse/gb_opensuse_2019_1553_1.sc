if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852555" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-16471" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-14 02:00:34 +0000 (Fri, 14 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for rubygem-rack (openSUSE-SU-2019:1553-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1553-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-rack'
  package(s) announced via the openSUSE-SU-2019:1553-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-rack fixes the following issues:

  Security issued fixed:

  - CVE-2018-16471: Fixed a cross-site scripting vulnerability via 'scheme'
  method (bsc#1116600).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1553=1" );
	script_tag( name: "affected", value: "'rubygem-rack' package(s) on openSUSE Leap 42.3." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-rack", rpm: "ruby2.1-rubygem-rack~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-rack-doc", rpm: "ruby2.1-rubygem-rack-doc~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-rack-testsuite", rpm: "ruby2.1-rubygem-rack-testsuite~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.2-rubygem-rack", rpm: "ruby2.2-rubygem-rack~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.2-rubygem-rack-doc", rpm: "ruby2.2-rubygem-rack-doc~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.2-rubygem-rack-testsuite", rpm: "ruby2.2-rubygem-rack-testsuite~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.3-rubygem-rack", rpm: "ruby2.3-rubygem-rack~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.3-rubygem-rack-doc", rpm: "ruby2.3-rubygem-rack-doc~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.3-rubygem-rack-testsuite", rpm: "ruby2.3-rubygem-rack-testsuite~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.4-rubygem-rack", rpm: "ruby2.4-rubygem-rack~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.4-rubygem-rack-doc", rpm: "ruby2.4-rubygem-rack-doc~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uby2.4-rubygem-rack-testsuite", rpm: "uby2.4-rubygem-rack-testsuite~1.6.11~7.3.1", rls: "openSUSELeap42.3" ) )){
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

