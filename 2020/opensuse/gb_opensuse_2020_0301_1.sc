if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853061" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-7041", "CVE-2020-7042", "CVE-2020-7043" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 14:58:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-03-05 04:00:40 +0000 (Thu, 05 Mar 2020)" );
	script_name( "openSUSE: Security Advisory for openfortivpn (openSUSE-SU-2020:0301-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0301-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00009.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openfortivpn'
  package(s) announced via the openSUSE-SU-2020:0301-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openfortivpn to version 1.12.0 fixes the following issues:

  - CVE-2020-7043: Fixed a TLS Certificate CommonName NULL Byte
  Vulnerability (boo#1165301).

  - CVE-2020-7042: Fixed use of uninitialized memory in X509_check_host
  (boo#1165300).

  - CVE-2020-7041: Fixed incorrect use of X509_check_host (boo#1165299).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-301=1" );
	script_tag( name: "affected", value: "'openfortivpn' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "openfortivpn", rpm: "openfortivpn~1.12.0~lp151.2.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openfortivpn-debuginfo", rpm: "openfortivpn-debuginfo~1.12.0~lp151.2.5.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openfortivpn-debugsource", rpm: "openfortivpn-debugsource~1.12.0~lp151.2.5.1", rls: "openSUSELeap15.1" ) )){
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

