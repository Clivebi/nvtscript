if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852543" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2017-6891", "CVE-2018-1000654" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:15:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-06-06 02:00:52 +0000 (Thu, 06 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for libtasn1 (openSUSE-SU-2019:1510-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1510-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00018.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtasn1'
  package(s) announced via the openSUSE-SU-2019:1510-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libtasn1 fixes the following issues:

  Security issues fixed:

  - CVE-2018-1000654: Fixed a denial of service in the asn1 parser
  (bsc#1105435).

  - CVE-2017-6891: Fixed a stack overflow in asn1_find_node() (bsc#1040621).

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1510=1" );
	script_tag( name: "affected", value: "'libtasn1' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtasn1", rpm: "libtasn1~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-6", rpm: "libtasn1-6~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-6-debuginfo", rpm: "libtasn1-6-debuginfo~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-debuginfo", rpm: "libtasn1-debuginfo~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-debugsource", rpm: "libtasn1-debugsource~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-devel", rpm: "libtasn1-devel~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-6-32bit", rpm: "libtasn1-6-32bit~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-6-debuginfo-32bit", rpm: "libtasn1-6-debuginfo-32bit~4.9~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtasn1-devel-32bit", rpm: "libtasn1-devel-32bit~4.9~6.1", rls: "openSUSELeap42.3" ) )){
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

