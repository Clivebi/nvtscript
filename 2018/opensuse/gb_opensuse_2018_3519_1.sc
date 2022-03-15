if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852103" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-10887", "CVE-2018-10888", "CVE-2018-11235", "CVE-2018-15501", "CVE-2018-8099" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)" );
	script_tag( name: "creation_date", value: "2018-10-27 06:25:10 +0200 (Sat, 27 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for libgit2 (openSUSE-SU-2018:3519-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:3519-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00078.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgit2'
  package(s) announced via the openSUSE-SU-2018:3519-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libgit2 fixes the following issues:

  - CVE-2018-8099: Fixed possible denial of service attack via different
  vectors by not being able to differentiate between these status codes
  (bsc#1085256).

  - CVE-2018-11235: With a crafted .gitmodules file, a malicious project can
  execute an arbitrary script on a machine that runs 'git clone

  - -recurse-submodules' because submodule 'names' are obtained from this
  file, and then appended to $GIT_DIR/modules, leading to directory
  traversal with '../' in a name. Finally, post-checkout hooks from a
  submodule are executed, bypassing the intended design in which hooks are
  not obtained from a remote server.  (bsc#1095219)

  - CVE-2018-10887: It has been discovered that an unexpected sign extension
  in git_delta_apply function in delta.c file may have lead to an integer
  overflow which in turn leads to an out of bound read, allowing to read
  before the base object. An attacker could have used this flaw to leak
  memory addresses or cause a Denial of Service. (bsc#1100613)

  - CVE-2018-10888: A missing check in git_delta_apply function in delta.c
  file, may lead to an out-of-bound read while reading a binary delta
  file. An attacker may use this flaw to cause a Denial of Service.
  (bsc#1100612)

  - CVE-2018-15501: A remote attacker can send a crafted smart-protocol 'ng'
  packet that lacks a '\\0' byte to trigger an out-of-bounds read that
  leads to DoS.  (bsc#1104641)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1314=1" );
	script_tag( name: "affected", value: "libgit2 on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libgit2-24", rpm: "libgit2-24~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgit2-24-debuginfo", rpm: "libgit2-24-debuginfo~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgit2-debugsource", rpm: "libgit2-debugsource~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgit2-devel", rpm: "libgit2-devel~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgit2-24-32bit", rpm: "libgit2-24-32bit~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgit2-24-debuginfo-32bit", rpm: "libgit2-24-debuginfo-32bit~0.24.1~10.3.1", rls: "openSUSELeap42.3" ) )){
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

