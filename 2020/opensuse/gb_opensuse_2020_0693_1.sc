if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853171" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-10722", "CVE-2020-10723", "CVE-2020-10724", "CVE-2020-10725", "CVE-2020-10726" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-05-23 03:00:53 +0000 (Sat, 23 May 2020)" );
	script_name( "openSUSE: Security Advisory for dpdk (openSUSE-SU-2020:0693-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0693-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00045.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk'
  package(s) announced via the openSUSE-SU-2020:0693-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dpdk fixes the following issues:

  Security issues fixed:

  - CVE-2020-10722: Fixed an integer overflow in vhost_user_set_log_base()
  (bsc#1171477).

  - CVE-2020-10723: Fixed an integer truncation in
  vhost_user_check_and_alloc_queue_pair() (bsc#1171477).

  - CVE-2020-10724: Fixed a missing inputs validation in Vhost-crypto
  (bsc#1171477).

  - CVE-2020-10725: Fixed a segfault caused by invalid virtio descriptors
  sent from a malicious guest (bsc#1171477).

  - CVE-2020-10726: Fixed a denial-of-service caused by
  VHOST_USER_GET_INFLIGHT_FD message flooding (bsc#1171477).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-693=1" );
	script_tag( name: "affected", value: "'dpdk' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel", rpm: "dpdk-devel~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel-debuginfo", rpm: "dpdk-devel-debuginfo~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples", rpm: "dpdk-examples~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples-debuginfo", rpm: "dpdk-examples-debuginfo~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~18.11.3_k4.12.14_lp151.28.48~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~18.11.3_k4.12.14_lp151.28.48~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools-debuginfo", rpm: "dpdk-tools-debuginfo~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11", rpm: "libdpdk-18_11~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11-debuginfo", rpm: "libdpdk-18_11-debuginfo~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-doc", rpm: "dpdk-doc~18.11.3~lp151.3.4.1", rls: "openSUSELeap15.1" ) )){
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

