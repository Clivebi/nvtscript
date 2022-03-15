if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853215" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-11863", "CVE-2020-11864", "CVE-2020-11865", "CVE-2020-11866" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-18 00:15:00 +0000 (Thu, 18 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-18 03:00:43 +0000 (Thu, 18 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for libEMF (openSUSE-SU-2020:0831-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0831-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libEMF'
  package(s) announced via the openSUSE-SU-2020:0831-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libEMF fixes the following issues:

  - CVE-2020-11863: Fixed an issue which could have led to denial of service
  (bsc#1171496).

  - CVE-2020-11864: Fixed an issue which could have led to denial of service
  (bsc#1171499).

  - CVE-2020-11865: Fixed an out of bounds memory access (bsc#1171497).

  - CVE-2020-11866: Fixed a use after free (bsc#1171498).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-831=1" );
	script_tag( name: "affected", value: "'libEMF' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libEMF-debuginfo", rpm: "libEMF-debuginfo~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF-debugsource", rpm: "libEMF-debugsource~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF-devel", rpm: "libEMF-devel~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF-utils", rpm: "libEMF-utils~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF-utils-debuginfo", rpm: "libEMF-utils-debuginfo~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF1", rpm: "libEMF1~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libEMF1-debuginfo", rpm: "libEMF1-debuginfo~1.0.7~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

