if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853157" );
	script_version( "2020-05-15T04:25:55+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-15 04:25:55 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-12 03:03:52 +0000 (Tue, 12 May 2020)" );
	script_name( "openSUSE: Security Advisory for rpmlint (openSUSE-SU-2020:0631-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0631-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00023.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpmlint'
  package(s) announced via the openSUSE-SU-2020:0631-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rpmlint fixes the following issues:

  - whitelist certmonger (bsc#1169365, bsc#1129452)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-631=1" );
	script_tag( name: "affected", value: "'rpmlint' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "rpmlint-mini", rpm: "rpmlint-mini~1.10~lp151.5.13.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpmlint-mini-debuginfo", rpm: "rpmlint-mini-debuginfo~1.10~lp151.5.13.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpmlint-mini-debugsource", rpm: "rpmlint-mini-debugsource~1.10~lp151.5.13.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpmlint", rpm: "rpmlint~1.10~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pmlint-tests-debugsource", rpm: "pmlint-tests-debugsource~84.87+git20181018.60e0249~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
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

