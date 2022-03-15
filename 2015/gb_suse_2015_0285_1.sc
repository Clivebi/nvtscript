if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850635" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-02-14 05:03:08 +0100 (Sat, 14 Feb 2015)" );
	script_cve_id( "CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for clamav (openSUSE-SU-2015:0285-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "clamav was updated to version 0.98.6 that fixes bugs and several security
  issues:

  * bsc#916217, CVE-2015-1461: Remote attackers can have unspecified impact
  via Yoda's crypter or mew packer files.

  * bsc#916214, CVE-2015-1462: Unspecified impact via acrafted upx packer
  file.

  * bsc#916215, CVE-2015-1463: Remote attackers can cause a denial
  of service via a crafted petite packer file.

  * bsc#915512, CVE-2014-9328: heap out of bounds condition with crafted
  upack packer files." );
	script_tag( name: "affected", value: "clamav on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0285-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.98.6~30.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debuginfo", rpm: "clamav-debuginfo~0.98.6~30.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debugsource", rpm: "clamav-debugsource~0.98.6~30.1", rls: "openSUSE13.1" ) )){
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

