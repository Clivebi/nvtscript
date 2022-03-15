if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851473" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 05:47:58 +0100 (Tue, 17 Jan 2017)" );
	script_cve_id( "CVE-2017-5208", "CVE-2017-5331", "CVE-2017-5332", "CVE-2017-5333" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-20 13:14:00 +0000 (Wed, 20 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for icoutils (openSUSE-SU-2017:0168-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icoutils'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for icoutils to version 0.31.1 fixes the following issues:

  - CVE-2017-5208: An integer overflow allows maliciously crafted files to
  cause DoS or code execution (boo#1018756).

  - CVE-2017-5331: Incorrect out of bounds checks in check_offset allow for
  DoS or code execution (boo#1018756).

  - CVE-2017-5332: Missing out of bounds checks in
  extract_group_icon_cursor_resource allow for DoS or code execution
  (boo#1018756).

  - CVE-2017-5333: Incorrect out of bounds checks in check_offset allow for
  DoS or code execution (boo#1018756)." );
	script_tag( name: "affected", value: "icoutils on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0168-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "icoutils", rpm: "icoutils~0.31.1~4.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icoutils-debuginfo", rpm: "icoutils-debuginfo~0.31.1~4.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "icoutils-debugsource", rpm: "icoutils-debugsource~0.31.1~4.3.1", rls: "openSUSE13.2" ) )){
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

