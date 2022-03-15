if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853833" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-30145" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-25 03:01:05 +0000 (Tue, 25 May 2021)" );
	script_name( "openSUSE: Security Advisory for mpv (openSUSE-SU-2021:0788-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0788-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QVXB4F67QODLPKYBZX7SBXTE7ESGKGOD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mpv'
  package(s) announced via the openSUSE-SU-2021:0788-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mpv fixes the following issues:

  - CVE-2021-30145: Fixed format string vulnerability allows user-assisted
       remote attackers to achieve code execution via a crafted m3u playlist
       file (boo#1186230)" );
	script_tag( name: "affected", value: "'mpv' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libmpv1", rpm: "libmpv1~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmpv1-debuginfo", rpm: "libmpv1-debuginfo~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv", rpm: "mpv~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv-debuginfo", rpm: "mpv-debuginfo~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv-debugsource", rpm: "mpv-debugsource~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv-devel", rpm: "mpv-devel~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv-bash-completion", rpm: "mpv-bash-completion~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mpv-zsh-completion", rpm: "mpv-zsh-completion~0.32.0+git.20200301T004003.e7bab0025f~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

