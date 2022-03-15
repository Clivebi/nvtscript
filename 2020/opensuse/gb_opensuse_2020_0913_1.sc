if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853244" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-18934", "CVE-2020-12662", "CVE-2020-12663" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-30 00:15:00 +0000 (Tue, 30 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-30 03:00:57 +0000 (Tue, 30 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for unbound (openSUSE-SU-2020:0913-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:0913-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00067.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unbound'
  package(s) announced via the openSUSE-SU-2020:0913-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for unbound fixes the following issues:

  - CVE-2020-12662: Fixed an issue where unbound could have been tricked
  into amplifying an incoming query into a large number of queries
  directed to a target (bsc#1171889).

  - CVE-2020-12663: Fixed an issue where malformed answers from upstream
  name servers could have been used to make unbound unresponsive
  (bsc#1171889).

  - CVE-2019-18934: Fixed a vulnerability in the IPSec module which could
  have allowed code execution after receiving a special crafted answer
  (bsc#1157268).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-913=1" );
	script_tag( name: "affected", value: "'unbound' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libunbound-devel-mini", rpm: "libunbound-devel-mini~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libunbound-devel-mini-debuginfo", rpm: "libunbound-devel-mini-debuginfo~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libunbound-devel-mini-debugsource", rpm: "libunbound-devel-mini-debugsource~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-munin", rpm: "unbound-munin~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libunbound2", rpm: "libunbound2~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libunbound2-debuginfo", rpm: "libunbound2-debuginfo~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound", rpm: "unbound~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-anchor", rpm: "unbound-anchor~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-anchor-debuginfo", rpm: "unbound-anchor-debuginfo~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-debuginfo", rpm: "unbound-debuginfo~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-debugsource", rpm: "unbound-debugsource~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-devel", rpm: "unbound-devel~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-python", rpm: "unbound-python~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-python-debuginfo", rpm: "unbound-python-debuginfo~1.6.8~lp152.9.3.1", rls: "openSUSELeap15.2" ) )){
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

