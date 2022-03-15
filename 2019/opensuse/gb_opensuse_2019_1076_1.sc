if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852378" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2019-1559", "CVE-2019-5737", "CVE-2019-5739" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 19:08:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:42:05 +0000 (Wed, 03 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for nodejs4 (openSUSE-SU-2019:1076-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1076-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00041.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs4'
  package(s) announced via the openSUSE-SU-2019:1076-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs4 fixes the following issues:

  Security issues fixed:

  - CVE-2019-5739: Fixed a potentially attack vector which could lead to
  Denial of Service when HTTP connection are kept active (bsc#1127533).

  - CVE-2019-5737: Fixed a potentially attack vector which could lead to
  Denial of Service when HTTP connection are kept active (bsc#1127532).

  - CVE-2019-1559: Fixed OpenSSL 0-byte Record Padding Oracle which under
  certain circumstances a TLS server can be forced to respond differently
  to a client and lead to the decryption of the data (bsc#1127080).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1076=1" );
	script_tag( name: "affected", value: "'nodejs4' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs4", rpm: "nodejs4~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debuginfo", rpm: "nodejs4-debuginfo~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debugsource", rpm: "nodejs4-debugsource~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-devel", rpm: "nodejs4-devel~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm4", rpm: "npm4~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-docs", rpm: "nodejs4-docs~4.9.1~23.1", rls: "openSUSELeap42.3" ) )){
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

