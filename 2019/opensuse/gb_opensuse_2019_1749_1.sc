if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852617" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2019-13012" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-07-21 02:00:40 +0000 (Sun, 21 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for glib2 (openSUSE-SU-2019:1749-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1749-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00022.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glib2'
  package(s) announced via the openSUSE-SU-2019:1749-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glib2 fixes the following issues:

  Security issue fixed:

  - CVE-2019-13012: Fixed improper restriction of file permissions when
  creating directories (bsc#1139959).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1749=1" );
	script_tag( name: "affected", value: "'glib2' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel", rpm: "glib2-devel~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-debuginfo", rpm: "glib2-devel-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-static", rpm: "glib2-devel-static~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-fam", rpm: "libgio-fam~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-fam-debuginfo", rpm: "libgio-fam-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gio-branding-upstream", rpm: "gio-branding-upstream~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-32bit", rpm: "glib2-devel-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-32bit-debuginfo", rpm: "glib2-devel-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-32bit", rpm: "glib2-tools-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-32bit-debuginfo", rpm: "glib2-tools-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit-debuginfo", rpm: "libgio-2_0-0-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-fam-32bit", rpm: "libgio-fam-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-fam-32bit-debuginfo", rpm: "libgio-fam-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit-debuginfo", rpm: "libglib-2_0-0-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit-debuginfo", rpm: "libgmodule-2_0-0-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit-debuginfo", rpm: "libgobject-2_0-0-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit", rpm: "libgthread-2_0-0-32bit~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit-debuginfo", rpm: "libgthread-2_0-0-32bit-debuginfo~2.54.3~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
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

