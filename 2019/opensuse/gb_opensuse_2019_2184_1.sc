if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852712" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-15892" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-26 02:01:29 +0000 (Thu, 26 Sep 2019)" );
	script_name( "openSUSE: Security Advisory for varnish (openSUSE-SU-2019:2184-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2184-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00069.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'varnish'
  package(s) announced via the openSUSE-SU-2019:2184-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for varnish fixes the following issues:

  Security issue fixed:

  - CVE-2019-15892: Fixed a potential denial of service by sending crafted
  HTTP/1 requests (boo#1149382).

  Non-security issues fixed:

  - Updated the package to release 6.2.1.

  - Added a thread pool watchdog which will restart the worker process if
  scheduling tasks onto worker threads appears stuck. The new parameter
  'thread_pool_watchdog' configures it.

  - Disabled error for clobbering, which caused bogus error in varnishtest.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2184=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2184=1" );
	script_tag( name: "affected", value: "'varnish' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvarnishapi2", rpm: "libvarnishapi2~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvarnishapi2-debuginfo", rpm: "libvarnishapi2-debuginfo~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish", rpm: "varnish~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-debuginfo", rpm: "varnish-debuginfo~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-debugsource", rpm: "varnish-debugsource~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-devel", rpm: "varnish-devel~6.2.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

