if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853475" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2020-14374", "CVE-2020-14375", "CVE-2020-14376", "CVE-2020-14377", "CVE-2020-14378" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 16:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-10-04 03:00:50 +0000 (Sun, 04 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for dpdk (openSUSE-SU-2020:1593-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1593-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk'
  package(s) announced via the openSUSE-SU-2020:1593-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dpdk fixes the following issues:

  - dpdk was updated to 18.11.9. For a list of fixes check:

  - 
  CVE-2020-14374, CVE-2020-14375, CVE-2020-14376, CVE-2020-14377, CVE-2020-14378:
  Fixed multiple issues where a malicious guest could harm the host
  using vhost crypto, including executing code in host (VM Escape),
  reading host application memory space to guest and causing partially
  denial of service in the host(bsc#1176590).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1593=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel", rpm: "dpdk-devel~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel-debuginfo", rpm: "dpdk-devel-debuginfo~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples", rpm: "dpdk-examples~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples-debuginfo", rpm: "dpdk-examples-debuginfo~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~18.11.9_k4.12.14_lp151.28.67~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~18.11.9_k4.12.14_lp151.28.67~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools-debuginfo", rpm: "dpdk-tools-debuginfo~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11", rpm: "libdpdk-18_11~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11-debuginfo", rpm: "libdpdk-18_11-debuginfo~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-doc", rpm: "dpdk-doc~18.11.9~lp151.3.8.1", rls: "openSUSELeap15.1" ) )){
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

