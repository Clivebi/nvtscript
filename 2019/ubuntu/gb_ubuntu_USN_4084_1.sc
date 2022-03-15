if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844123" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-28 13:15:00 +0000 (Wed, 28 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-02 02:00:35 +0000 (Fri, 02 Aug 2019)" );
	script_name( "Ubuntu Update for python-django USN-4084-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4084-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-4084-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-django'
  package(s) announced via the USN-4084-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Django incorrectly handled the Truncator function. A
remote attacker could possibly use this issue to cause Django to consume
resources, leading to a denial of service. (CVE-2019-14232)

It was discovered that Django incorrectly handled the strip_tags function.
A remote attacker could possibly use this issue to cause Django to consume
resources, leading to a denial of service. (CVE-2019-14233)

It was discovered that Django incorrectly handled certain lookups in the
PostgreSQL support. A remote attacker could possibly use this issue to
perform SQL injection attacks. (CVE-2019-14234)

It was discovered that Django incorrectly handled certain invalid UTF-8
octet sequences. A remote attacker could possibly use this issue to cause
Django to consume resources, leading to a denial of service.
(CVE-2019-14235)" );
	script_tag( name: "affected", value: "'python-django' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1:1.11.11-1ubuntu1.5", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1:1.11.11-1ubuntu1.5", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1:1.11.20-1ubuntu0.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1:1.11.20-1ubuntu0.2", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1.8.7-1ubuntu5.10", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1.8.7-1ubuntu5.10", rls: "UBUNTU16.04 LTS" ) )){
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
