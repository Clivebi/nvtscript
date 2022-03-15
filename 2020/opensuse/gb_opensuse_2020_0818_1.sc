if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853214" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2020-0543" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-29 03:15:00 +0000 (Sun, 29 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 03:00:55 +0000 (Wed, 17 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for xen (openSUSE-SU-2020:0818-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0818-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00025.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2020:0818-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen to version 4.12.3 fixes the following issues:

  - CVE-2020-0543: Fixed a side channel attack against special registers
  which could have resulted in leaking of read values to cores other than
  the one which called it. This attack is known as Special Register Buffer
  Data Sampling (SRBDS) or 'CrossTalk' (bsc#1172205).

  - Added support for new 64bit libxl memory API (bsc#1167007 and
  bsc#1157490).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-818=1" );
	script_tag( name: "affected", value: "'xen' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit-debuginfo", rpm: "xen-libs-32bit-debuginfo~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.12.3_02~lp151.2.18.2", rls: "openSUSELeap15.1" ) )){
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
