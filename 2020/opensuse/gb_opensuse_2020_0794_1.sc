if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853203" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-20807" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 14:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-06-12 03:01:32 +0000 (Fri, 12 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for vim (openSUSE-SU-2020:0794-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0794-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00018.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vim'
  package(s) announced via the openSUSE-SU-2020:0794-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for vim fixes the following issues:

  - CVE-2019-20807: Fixed an issue where escaping from the restrictive mode
  of vim was possible using interfaces (bsc#1172225).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-794=1" );
	script_tag( name: "affected", value: "'vim' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "gvim", rpm: "gvim~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvim-debuginfo", rpm: "gvim-debuginfo~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vim", rpm: "vim~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vim-debuginfo", rpm: "vim-debuginfo~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vim-debugsource", rpm: "vim-debugsource~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vim-data", rpm: "vim-data~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vim-data-common", rpm: "vim-data-common~8.0.1568~lp151.5.6.1", rls: "openSUSELeap15.1" ) )){
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

