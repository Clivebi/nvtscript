if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853143" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-15681", "CVE-2019-15690", "CVE-2019-20788" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 19:46:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-05-12 03:03:21 +0000 (Tue, 12 May 2020)" );
	script_name( "openSUSE: Security Advisory for LibVNCServer (openSUSE-SU-2020:0624-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0624-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00027.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'LibVNCServer'
  package(s) announced via the openSUSE-SU-2020:0624-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for LibVNCServer fixes the following issues:

  - CVE-2019-15690: Fixed a heap buffer overflow (bsc#1160471).

  - CVE-2019-15681: Fixed a memory leak which could have allowed to a remote
  attacker to read stack memory (bsc#1155419).

  - CVE-2019-20788: Fixed an integer overflow and heap-based buffer overflow
  via a large height or width value (bsc#1170441).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-624=1" );
	script_tag( name: "affected", value: "'LibVNCServer' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "LibVNCServer-debugsource", rpm: "LibVNCServer-debugsource~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "LibVNCServer-devel", rpm: "LibVNCServer-devel~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvncclient0", rpm: "libvncclient0~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvncclient0-debuginfo", rpm: "libvncclient0-debuginfo~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvncserver0", rpm: "libvncserver0~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvncserver0-debuginfo", rpm: "libvncserver0-debuginfo~0.9.10~lp151.7.3.1", rls: "openSUSELeap15.1" ) )){
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

