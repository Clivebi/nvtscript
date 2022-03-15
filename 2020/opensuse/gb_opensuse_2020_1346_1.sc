if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853408" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-15049", "CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-17 15:39:00 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-09-06 03:00:46 +0000 (Sun, 06 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for squid (openSUSE-SU-2020:1346-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1346-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00012.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the openSUSE-SU-2020:1346-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for squid fixes the following issues:

  squid was updated to version 4.13:

  - CVE-2020-24606: Fix livelocking in peerDigestHandleReply (bsc#1175671).

  - CVE-2020-15811: Improve Transfer-Encoding handling (bsc#1175665).

  - CVE-2020-15810: Enforce token characters for field-name (bsc#1175664).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1346=1" );
	script_tag( name: "affected", value: "'squid' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~4.13~lp151.2.24.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~4.13~lp151.2.24.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debugsource", rpm: "squid-debugsource~4.13~lp151.2.24.1", rls: "openSUSELeap15.1" ) )){
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

