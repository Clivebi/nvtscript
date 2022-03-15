if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851804" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-30 05:51:01 +0200 (Sat, 30 Jun 2018)" );
	script_cve_id( "CVE-2018-3760" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for rubygem-sprockets (openSUSE-SU-2018:1854-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-sprockets'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-sprockets fixes the following issues:

  The following security vulnerability was addressed:

  - CVE-2018-3760: Fixed a directory traversal issue in
  sprockets/server.rb:forbidden_request?(), which allowed remote attackers
  to read arbitrary files via specially crafted requests. (boo#1098369)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-686=1" );
	script_tag( name: "affected", value: "rubygem-sprockets on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1854-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00052.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-sprockets", rpm: "ruby2.1-rubygem-sprockets~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-sprockets-doc", rpm: "ruby2.1-rubygem-sprockets-doc~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.2-rubygem-sprockets", rpm: "ruby2.2-rubygem-sprockets~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.2-rubygem-sprockets-doc", rpm: "ruby2.2-rubygem-sprockets-doc~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.3-rubygem-sprockets", rpm: "ruby2.3-rubygem-sprockets~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.3-rubygem-sprockets-doc", rpm: "ruby2.3-rubygem-sprockets-doc~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.4-rubygem-sprockets", rpm: "ruby2.4-rubygem-sprockets~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.4-rubygem-sprockets-doc", rpm: "ruby2.4-rubygem-sprockets-doc~3.3.5~5.3.1", rls: "openSUSELeap42.3" ) )){
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

