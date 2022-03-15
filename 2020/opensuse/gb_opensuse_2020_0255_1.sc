if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853045" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_cve_id( "CVE-2019-18900" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-27 23:15:00 +0000 (Thu, 27 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-28 04:01:56 +0000 (Fri, 28 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for libsolv, (openSUSE-SU-2020:0255-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0255-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsolv, '
  package(s) announced via the openSUSE-SU-2020:0255-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libsolv, libzypp, zypper fixes the following issues:


  Security issue fixed:

  - CVE-2019-18900: Fixed assert cookie file that was world readable
  (bsc#1158763).

  Bug fixes

  - Fixed removing orphaned packages dropped by to-be-installed products
  (bsc#1155819).

  - Adds libzypp API to mark all obsolete kernels according to the existing
  purge-kernel script rules (bsc#1155198).

  - Do not enforce 'en' being in RequestedLocales If the user decides to
  have a system without explicit language support he may do so
  (bsc#1155678).

  - Load only target resolvables for zypper rm (bsc#1157377).

  - Fix broken search by filelist (bsc#1135114).

  - Replace python by a bash script in zypper-log (fixes#304, fixes#306,
  bsc#1156158).

  - Do not sort out requested locales which are not available (bsc#1155678).

  - Prevent listing duplicate matches in tables. XML result is provided
  within the new list-patches-byissue element (bsc#1154805).

  - XML add patch issue-date and issue-list (bsc#1154805).

  - Fix zypper lp --cve/bugzilla/issue options (bsc#1155298).

  - Always execute commit when adding/removing locales (fixes bsc#1155205).

  - Fix description of --table-style, -s in man page (bsc#1154804).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-255=1" );
	script_tag( name: "affected", value: "'libsolv, ' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsolv-debuginfo", rpm: "libsolv-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-debugsource", rpm: "libsolv-debugsource~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-demo", rpm: "libsolv-demo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-demo-debuginfo", rpm: "libsolv-demo-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-devel", rpm: "libsolv-devel~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-devel-debuginfo", rpm: "libsolv-devel-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools", rpm: "libsolv-tools~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsolv-tools-debuginfo", rpm: "libsolv-tools-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp", rpm: "libzypp~17.19.0~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debuginfo", rpm: "libzypp-debuginfo~17.19.0~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debugsource", rpm: "libzypp-debugsource~17.19.0~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel", rpm: "libzypp-devel~17.19.0~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel-doc", rpm: "libzypp-devel-doc~17.19.0~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv", rpm: "perl-solv~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-solv-debuginfo", rpm: "perl-solv-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-solv", rpm: "python-solv~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-solv-debuginfo", rpm: "python-solv-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-solv", rpm: "python3-solv~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-solv-debuginfo", rpm: "python3-solv-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-solv", rpm: "ruby-solv~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-solv-debuginfo", rpm: "ruby-solv-debuginfo~0.7.10~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper", rpm: "zypper~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debuginfo", rpm: "zypper-debuginfo~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debugsource", rpm: "zypper-debugsource~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-aptitude", rpm: "zypper-aptitude~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-log", rpm: "zypper-log~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-needs-restarting", rpm: "zypper-needs-restarting~1.14.33~lp151.2.10.1", rls: "openSUSELeap15.1" ) )){
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

