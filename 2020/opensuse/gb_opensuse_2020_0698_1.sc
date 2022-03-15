if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853178" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-10030", "CVE-2020-10995", "CVE-2020-12244" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-14 19:15:00 +0000 (Sun, 14 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-24 03:00:42 +0000 (Sun, 24 May 2020)" );
	script_name( "openSUSE: Security Advisory for pdns-recursor (openSUSE-SU-2020:0698-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0698-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00052.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pdns-recursor'
  package(s) announced via the openSUSE-SU-2020:0698-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for pdns-recursor fixes the following issues:

  - update to 4.1.16

  * fixes an issue where records in the answer section of a NXDOMAIN
  response lacking an SOA were not properly validated (CVE-2020-12244,
  boo#1171553)

  * fixes an issue where invalid hostname on the server can result in
  disclosure of invalid memory (CVE-2020-10030, boo#1171553)

  * fixes an issue in the DNS protocol has been found that allows
  malicious parties to use recursive DNS services to attack third party
  authoritative name servers (CVE-2020-10995, boo#1171553)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-698=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-698=1" );
	script_tag( name: "affected", value: "'pdns-recursor' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "pdns-recursor", rpm: "pdns-recursor~4.1.12~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pdns-recursor-debuginfo", rpm: "pdns-recursor-debuginfo~4.1.12~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pdns-recursor-debugsource", rpm: "pdns-recursor-debugsource~4.1.12~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

