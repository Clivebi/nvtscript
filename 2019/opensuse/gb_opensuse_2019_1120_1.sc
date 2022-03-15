if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852370" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2018-10733" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:41:54 +0000 (Wed, 03 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for libgxps (openSUSE-SU-2019:1120-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1120-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00005.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgxps'
  package(s) announced via the openSUSE-SU-2019:1120-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libgxps fixes the following issues:

  - CVE-2018-10733: Fixed a heap-based buffer over-read issue in
  ft_font_face_hash (bsc#1092125).


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1120=1" );
	script_tag( name: "affected", value: "'libgxps' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libgxps-debuginfo", rpm: "libgxps-debuginfo~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps-debugsource", rpm: "libgxps-debugsource~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps-devel", rpm: "libgxps-devel~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps-tools", rpm: "libgxps-tools~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps-tools-debuginfo", rpm: "libgxps-tools-debuginfo~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps2", rpm: "libgxps2~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgxps2-debuginfo", rpm: "libgxps2-debuginfo~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GXPS-0_1", rpm: "typelib-1_0-GXPS-0_1~0.3.0~lp150.3.3.2", rls: "openSUSELeap15.0" ) )){
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

