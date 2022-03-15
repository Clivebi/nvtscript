if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851947" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-25 06:00:31 +0200 (Thu, 25 Oct 2018)" );
	script_cve_id( "CVE-2017-7500", "CVE-2017-7501" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for rpm (openSUSE-SU-2018:3373-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rpm fixes the following issues:

  These security issues were fixed:

  - CVE-2017-7500: rpm did not properly handle RPM installations when a
  destination path was a symbolic link to a directory, possibly changing
  ownership and permissions of an arbitrary directory, and RPM files being
  placed in an arbitrary destination (bsc#943457).

  - CVE-2017-7501: rpm used temporary files with predictable names when
  installing an RPM. An attacker with ability to write in a directory
  where files will be installed could create symbolic links to an
  arbitrary location and modify content, and possibly permissions to
  arbitrary files, which could be used for denial of service or possibly
  privilege escalation (bsc#943457)

  This non-security issue was fixed:

  - Use ksym-provides tool [bsc#1077692]

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1246=1" );
	script_tag( name: "affected", value: "rpm on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:3373-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00058.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm", rpm: "python3-rpm~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm-debuginfo", rpm: "python3-rpm-debuginfo~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm-debugsource", rpm: "python3-rpm-debugsource~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm", rpm: "rpm~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build", rpm: "rpm-build~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build-debuginfo", rpm: "rpm-build-debuginfo~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debuginfo", rpm: "rpm-debuginfo~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debugsource", rpm: "rpm-debugsource~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-devel", rpm: "rpm-devel~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python", rpm: "rpm-python~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python-debuginfo", rpm: "rpm-python-debuginfo~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python-debugsource", rpm: "rpm-python-debugsource~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-32bit", rpm: "rpm-32bit~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pm-debuginfo-32bit", rpm: "pm-debuginfo-32bit~4.11.2~14.10.1", rls: "openSUSELeap42.3" ) )){
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

