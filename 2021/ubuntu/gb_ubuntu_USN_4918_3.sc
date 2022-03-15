if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844920" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-1252", "CVE-2021-1404", "CVE-2021-1405" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 19:56:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-05-05 03:01:06 +0000 (Wed, 05 May 2021)" );
	script_name( "Ubuntu: Security Advisory for clamav (USN-4918-3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4918-3" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/005998.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the USN-4918-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4918-1 fixed vulnerabilities in ClamAV. The updated package could
fail to properly scan in some situations. This update fixes
the problem.

Original advisory details:

It was discovered that ClamAV incorrectly handled parsing Excel documents.
A remote attacker could possibly use this issue to cause ClamAV to hang,
resulting in a denial of service. (CVE-2021-1252)

It was discovered that ClamAV incorrectly handled parsing PDF documents. A
remote attacker could possibly use this issue to cause ClamAV to crash,
resulting in a denial of service. (CVE-2021-1404)

It was discovered that ClamAV incorrectly handled parsing email. A remote
attacker could possibly use this issue to cause ClamAV to crash, resulting
in a denial of service. (CVE-2021-1405)" );
	script_tag( name: "affected", value: "'clamav' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.103.2+dfsg-0ubuntu0.20.04.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libclamav9", ver: "0.103.2+dfsg-0ubuntu0.20.04.2", rls: "UBUNTU20.04 LTS" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.103.2+dfsg-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libclamav9", ver: "0.103.2+dfsg-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.103.2+dfsg-0ubuntu0.20.10.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libclamav9", ver: "0.103.2+dfsg-0ubuntu0.20.10.2", rls: "UBUNTU20.10" ) )){
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

