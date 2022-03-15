if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851469" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-11 05:38:52 +0100 (Wed, 11 Jan 2017)" );
	script_cve_id( "CVE-2016-8654", "CVE-2016-9395", "CVE-2016-9398", "CVE-2016-9560", "CVE-2016-9591" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for jasper (openSUSE-SU-2017:0101-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jasper fixes the following issues:

  - CVE-2016-8654: Heap-based buffer overflow in QMFB code in JPC codec.
  (bsc#1012530)

  - CVE-2016-9395: Invalid jasper files could lead to abort of the library
  caused by attacker provided image. (bsc#1010977)

  - CVE-2016-9398: Invalid jasper files could lead to abort of the library
  caused by attacker provided image. (bsc#1010979)

  - CVE-2016-9560: Stack-based buffer overflow in jpc_tsfb_getbands2.
  (bsc#1011830)

  - CVE-2016-9591: Use-after-free on heap in jas_matrix_destroy.
  (bsc#1015993)

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "jasper on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0101-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "jasper", rpm: "jasper~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debuginfo", rpm: "jasper-debuginfo~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debugsource", rpm: "jasper-debugsource~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper-devel", rpm: "libjasper-devel~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper1", rpm: "libjasper1~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper1-debuginfo", rpm: "libjasper1-debuginfo~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper1-32bit", rpm: "libjasper1-32bit~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper1-debuginfo-32bit", rpm: "libjasper1-debuginfo-32bit~1.900.14~170.1", rls: "openSUSELeap42.1" ) )){
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

