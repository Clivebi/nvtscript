if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852578" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2017-2579", "CVE-2017-2580" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-24 15:15:00 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-25 02:00:53 +0000 (Tue, 25 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for netpbm (openSUSE-SU-2019:1605-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1605-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00056.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netpbm'
  package(s) announced via the openSUSE-SU-2019:1605-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for netpbm fixes the following issues:

  Security issues fixed:

  - CVE-2017-2579: Fixed out-of-bounds read in expandCodeOntoStack()
  (bsc#1024288).

  - CVE-2017-2580: Fixed out-of-bounds write of heap data in
  addPixelToRaster() function (bsc#1024291).

  - create netpbm-vulnerable subpackage and move pstopnm there, as
  ghostscript is used to convert (bsc#1136936)


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1605=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1605=1" );
	script_tag( name: "affected", value: "'netpbm' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libnetpbm-devel", rpm: "libnetpbm-devel~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetpbm11", rpm: "libnetpbm11~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetpbm11-debuginfo", rpm: "libnetpbm11-debuginfo~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm", rpm: "netpbm~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-debuginfo", rpm: "netpbm-debuginfo~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-debugsource", rpm: "netpbm-debugsource~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-vulnerable", rpm: "netpbm-vulnerable~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "netpbm-vulnerable-debuginfo", rpm: "netpbm-vulnerable-debuginfo~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetpbm11-32bit", rpm: "libnetpbm11-32bit~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnetpbm11-32bit-debuginfo", rpm: "libnetpbm11-32bit-debuginfo~10.80.1~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

