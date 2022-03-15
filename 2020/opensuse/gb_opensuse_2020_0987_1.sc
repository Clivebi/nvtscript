if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853280" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2020-10756" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-01 14:15:00 +0000 (Thu, 01 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-07-19 03:01:15 +0000 (Sun, 19 Jul 2020)" );
	script_name( "openSUSE: Security Advisory for slirp4netns (openSUSE-SU-2020:0987-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0987-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00035.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'slirp4netns'
  package(s) announced via the openSUSE-SU-2020:0987-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for slirp4netns fixes the following issues:

  - Update to 0.4.7 (bsc#1172380)

  * libslirp: update to v4.3.1 (Fix CVE-2020-10756)

  * Fix config_from_options() to correctly enable ipv6

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-987=1" );
	script_tag( name: "affected", value: "'slirp4netns' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "slirp4netns", rpm: "slirp4netns~0.4.7~lp151.2.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slirp4netns-debuginfo", rpm: "slirp4netns-debuginfo~0.4.7~lp151.2.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "slirp4netns-debugsource", rpm: "slirp4netns-debugsource~0.4.7~lp151.2.12.1", rls: "openSUSELeap15.1" ) )){
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

