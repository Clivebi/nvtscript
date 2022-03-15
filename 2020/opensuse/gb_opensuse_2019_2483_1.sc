if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852898" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2019-17498" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 17:29:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:43:38 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for libssh2_org (openSUSE-SU-2019:2483-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2483-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00026.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh2_org'
  package(s) announced via the openSUSE-SU-2019:2483-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libssh2_org fixes the following issue:

  - CVE-2019-17498: Fixed an integer overflow in a bounds check that might
  have led to the disclosure of sensitive information or a denial of
  service (bsc#1154862).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2483=1" );
	script_tag( name: "affected", value: "'libssh2_org' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1", rpm: "libssh2-1~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-debuginfo", rpm: "libssh2-1-debuginfo~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-devel", rpm: "libssh2-devel~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2_org-debugsource", rpm: "libssh2_org-debugsource~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-32bit", rpm: "libssh2-1-32bit~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-32bit-debuginfo", rpm: "libssh2-1-32bit-debuginfo~1.8.0~lp151.6.3.1", rls: "openSUSELeap15.1" ) )){
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

