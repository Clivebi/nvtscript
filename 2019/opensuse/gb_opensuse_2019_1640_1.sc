if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852588" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-3860" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 12:31:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-06-28 02:00:46 +0000 (Fri, 28 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for libssh2_org (openSUSE-SU-2019:1640-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1640-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00072.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh2_org'
  package(s) announced via the openSUSE-SU-2019:1640-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libssh2_org fixes the following issues:

  - Fix the previous fix for CVE-2019-3860 (bsc#1136570, bsc#1128481)
  (Out-of-bounds reads with specially crafted SFTP packets)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1640=1" );
	script_tag( name: "affected", value: "'libssh2_org' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1", rpm: "libssh2-1~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-debuginfo", rpm: "libssh2-1-debuginfo~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-devel", rpm: "libssh2-devel~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2_org-debugsource", rpm: "libssh2_org-debugsource~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-32bit", rpm: "libssh2-1-32bit~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-debuginfo-32bit", rpm: "libssh2-1-debuginfo-32bit~1.4.3~19.9.1", rls: "openSUSELeap42.3" ) )){
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

