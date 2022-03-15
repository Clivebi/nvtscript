if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853974" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2020-11078", "CVE-2021-21240" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-12 14:56:00 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:08:23 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for python-httplib2 (openSUSE-SU-2021:1806-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1806-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DTGWJY2VML3YAAFAOOYJAQP5SZ4X6XWG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-httplib2'
  package(s) announced via the openSUSE-SU-2021:1806-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-httplib2 fixes the following issues:

  - Update to version 0.19.0 (bsc#1182053).

  - CVE-2021-21240: Fixed regular expression denial of service via malicious
       header (bsc#1182053).

  - CVE-2020-11078: Fixed unescaped part of uri where an attacker could
       change request headers and body (bsc#1182053)." );
	script_tag( name: "affected", value: "'python-httplib2' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "python2-httplib2", rpm: "python2-httplib2~0.19.0~3.3.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-httplib2", rpm: "python3-httplib2~0.19.0~3.3.1", rls: "openSUSELeap15.3" ) )){
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

