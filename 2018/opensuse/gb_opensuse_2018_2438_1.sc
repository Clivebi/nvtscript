if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851982" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-10860" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-23 10:29:00 +0000 (Sun, 23 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:26:31 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for perl-Archive-Zip (openSUSE-SU-2018:2438-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2438-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00069.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Archive-Zip'
  package(s) announced via the openSUSE-SU-2018:2438-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl-Archive-Zip fixes the following security issue:

  - CVE-2018-10860: Prevent directory traversal caused by not properly
  sanitizing paths while extracting zip files. An attacker able to provide
  a specially crafted archive for processing could have used this flaw to
  write or overwrite arbitrary files in the context of the perl
  interpreter (bsc#1099497)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-904=1" );
	script_tag( name: "affected", value: "perl-Archive-Zip on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-Archive-Zip", rpm: "perl-Archive-Zip~1.60~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

