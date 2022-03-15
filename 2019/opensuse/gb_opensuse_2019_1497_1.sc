if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852532" );
	script_version( "2020-01-31T08:04:39+0000" );
	script_cve_id( "CVE-2012-5784", "CVE-2014-3596" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-06-04 02:00:48 +0000 (Tue, 04 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for axis (openSUSE-SU-2019:1497-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1497-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'axis'
  package(s) announced via the openSUSE-SU-2019:1497-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for axis fixes the following issues:

  Security issue fixed:

  - CVE-2012-5784, CVE-2014-3596: Fixed missing connection hostname check
  against X.509 certificate name (bsc#1134598).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1497=1" );
	script_tag( name: "affected", value: "'axis' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "axis", rpm: "axis~1.4~lp150.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "axis-manual", rpm: "axis-manual~1.4~lp150.9.1", rls: "openSUSELeap15.0" ) )){
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

