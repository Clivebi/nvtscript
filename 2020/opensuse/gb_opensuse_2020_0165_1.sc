if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853023" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2019-18902", "CVE-2020-7216" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-04 15:07:00 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-02-05 04:01:12 +0000 (Wed, 05 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for wicked (openSUSE-SU-2020:0165-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0165-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00005.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wicked'
  package(s) announced via the openSUSE-SU-2020:0165-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wicked fixes the following issues:

  - CVE-2019-18902: Fixed a use-after-free when receiving invalid DHCP6
  client options (bsc#1160903).

  - CVE-2020-7216: Fixed a potential denial of service via a memory leak
  when processing packets with missing message type option in DHCP4
  (bsc#1160905).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-165=1" );
	script_tag( name: "affected", value: "'wicked' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "wicked", rpm: "wicked~0.6.60~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wicked-debuginfo", rpm: "wicked-debuginfo~0.6.60~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wicked-debugsource", rpm: "wicked-debugsource~0.6.60~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wicked-service", rpm: "wicked-service~0.6.60~lp151.2.6.1", rls: "openSUSELeap15.1" ) )){
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

