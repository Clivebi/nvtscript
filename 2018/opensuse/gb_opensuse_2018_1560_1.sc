if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851775" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-06 05:47:43 +0200 (Wed, 06 Jun 2018)" );
	script_cve_id( "CVE-2018-1059" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-21 10:29:00 +0000 (Tue, 21 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for dpdk-thunderxdpdk (openSUSE-SU-2018:1560-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk-thunderxdpdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following issues:

  - CVE-2018-1059: The DPDK vhost-user interface did not check to verify
  that all the requested guest physical range was mapped and contiguous
  when performing Guest Physical Addresses to Host Virtual Addresses
  translations. This may have lead to a malicious guest exposing
  vhost-user backend process memory (bsc#1089638).

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-558=1" );
	script_tag( name: "affected", value: "dpdk-thunderxdpdk on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:1560-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00005.html" );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel", rpm: "dpdk-devel~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-devel-debuginfo", rpm: "dpdk-devel-debuginfo~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples", rpm: "dpdk-examples~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-examples-debuginfo", rpm: "dpdk-examples-debuginfo~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~16.11.6_k4.4.132_53~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~16.11.6_k4.4.132_53~6.5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-doc", rpm: "dpdk-doc~16.11.6~6.5.1", rls: "openSUSELeap42.3" ) )){
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

