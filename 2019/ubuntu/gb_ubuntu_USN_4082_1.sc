if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844117" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-11782", "CVE-2019-0203" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 15:33:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-08-01 02:01:17 +0000 (Thu, 01 Aug 2019)" );
	script_name( "Ubuntu Update for subversion USN-4082-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4082-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-4082-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'subversion'
  package(s) announced via the USN-4082-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ace Olszowka discovered that Subversion incorrectly handled certain
svnserve requests. A remote attacker could possibly use this issue to
cause svnserver to crash, resulting in a denial of service.
(CVE-2018-11782)

Tomas Bortoli discovered that Subversion incorrectly handled certain
svnserve requests. A remote attacker could possibly use this issue to
cause svnserver to crash, resulting in a denial of service. (CVE-2019-0203)" );
	script_tag( name: "affected", value: "'subversion' package(s) on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libsvn1", ver: "1.9.3-2ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "subversion", ver: "1.9.3-2ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
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

