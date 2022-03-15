if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852308" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-02-20 04:07:34 +0100 (Wed, 20 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for runc (openSUSE-SU-2019:0208-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0208-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00048.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'runc'
  package(s) announced via the openSUSE-SU-2019:0208-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for runc fixes the following issues:

  Security vulnerabilities addressed:

  - CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
  avoid write attacks to the host runc binary, which could lead to a
  container breakout (bsc#1121967)

  - CVE-2018-16873: Fix a remote command execution during 'go get -u'
  (boo#1118897)

  - CVE-2018-16874: Fix a directory traversal in 'go get' via curly braces
  in import paths (boo#1118898)

  - CVE-2018-16875: Fix a CPU denial of service issue (boo#1118899)

  Other changes and bug fixes:

  - Update go requirements to  = go1.10

  - Create a symlink in /usr/bin/runc to enable rootless Podman and Buildah.

  - Make use of %license macro

  - Remove 'go test' from %check section, as it has only ever caused us
  problems and hasn't (as far as I remember) ever caught a
  release-blocking issue. Smoke testing has been far more useful.
  (boo#1095817)

  - Upgrade to runc v1.0.0~rc6.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-208=1" );
	script_tag( name: "affected", value: "runc on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "runc", rpm: "runc~1.0.0~rc6~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "runc-debuginfo", rpm: "runc-debuginfo~1.0.0~rc6~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unc-test", rpm: "unc-test~1.0.0~rc6~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

