if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844599" );
	script_version( "2021-07-09T02:00:48+0000" );
	script_cve_id( "CVE-2020-10753", "CVE-2020-12059", "CVE-2020-1760" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-09 02:00:48 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-24 17:15:00 +0000 (Thu, 24 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-23 03:00:20 +0000 (Wed, 23 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for ceph (USN-4528-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4528-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005638.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceph'
  package(s) announced via the USN-4528-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Adam Mohammed discovered that Ceph incorrectly handled certain CORS
ExposeHeader tags. A remote attacker could possibly use this issue to
perform an HTTP header injection attack. (CVE-2020-10753)

Lei Cao discovered that Ceph incorrectly handled certain POST requests with
invalid tagging XML. A remote attacker could possibly use this issue to
cause Ceph to crash, leading to a denial of service. This issue only
affected Ubuntu 18.04 LTS. (CVE-2020-12059)

Robin H. Johnson discovered that Ceph incorrectly handled certain S3
requests. A remote attacker could possibly use this issue to perform a
XSS attack. (CVE-2020-1760)" );
	script_tag( name: "affected", value: "'ceph' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ceph", ver: "12.2.13-0ubuntu0.18.04.4", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-base", ver: "12.2.13-0ubuntu0.18.04.4", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-common", ver: "12.2.13-0ubuntu0.18.04.4", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ceph", ver: "10.2.11-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "ceph-common", ver: "10.2.11-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) )){
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

