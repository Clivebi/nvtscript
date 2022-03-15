if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851965" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2017-18199", "CVE-2017-18201" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:23:38 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for libcdio (openSUSE-SU-2018:2294-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2294-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00040.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcdio'
  package(s) announced via the openSUSE-SU-2018:2294-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libcdio fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2017-18199: Fixed a NULL pointer dereference in realloc_symlink in
  rock.c (bsc#1082821)

  - CVE-2017-18201: Fixed a double free vulnerability in
  get_cdtext_generic() in _cdio_generic.c (bsc#1082877)

  - Fixed several memory leaks (bsc#1082821)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-857=1" );
	script_tag( name: "affected", value: "libcdio on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libcdio++0", rpm: "libcdio++0~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio++0-debuginfo", rpm: "libcdio++0-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio-debugsource", rpm: "libcdio-debugsource~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio-devel", rpm: "libcdio-devel~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio16", rpm: "libcdio16~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio16-debuginfo", rpm: "libcdio16-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libiso9660-10", rpm: "libiso9660-10~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libiso9660-10-debuginfo", rpm: "libiso9660-10-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudf0", rpm: "libudf0~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudf0-debuginfo", rpm: "libudf0-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cdio-utils", rpm: "cdio-utils~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cdio-utils-debuginfo", rpm: "cdio-utils-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cdio-utils-debugsource", rpm: "cdio-utils-debugsource~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio++0-32bit", rpm: "libcdio++0-32bit~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio++0-32bit-debuginfo", rpm: "libcdio++0-32bit-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio16-32bit", rpm: "libcdio16-32bit~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcdio16-32bit-debuginfo", rpm: "libcdio16-32bit-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libiso9660-10-32bit", rpm: "libiso9660-10-32bit~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libiso9660-10-32bit-debuginfo", rpm: "libiso9660-10-32bit-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudf0-32bit", rpm: "libudf0-32bit~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudf0-32bit-debuginfo", rpm: "libudf0-32bit-debuginfo~0.94~lp150.5.3.1", rls: "openSUSELeap15.0" ) )){
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

