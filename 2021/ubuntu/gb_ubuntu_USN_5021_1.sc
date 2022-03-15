if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845009" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2021-22898", "CVE-2021-22925", "CVE-2021-22924" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-16 17:23:00 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 03:00:32 +0000 (Fri, 23 Jul 2021)" );
	script_name( "Ubuntu: Security Advisory for curl (USN-5021-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5021-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006116.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the USN-5021-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Harry Sintonen and Tomas Hoger discovered that curl incorrectly handled
TELNET connections when the -t option was used on the command line.
Uninitialized data possibly containing sensitive information could be sent
to the remote server, contrary to expectations. (CVE-2021-22898,
CVE-2021-22925)

Harry Sintonen discovered that curl incorrectly reused connections in the
connection pool. This could result in curl reusing the wrong connections.
(CVE-2021-22924)" );
	script_tag( name: "affected", value: "'curl' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.58.0-2ubuntu3.14", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.58.0-2ubuntu3.14", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.58.0-2ubuntu3.14", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.58.0-2ubuntu3.14", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.68.0-1ubuntu2.6", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.68.0-1ubuntu2.6", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.68.0-1ubuntu2.6", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libcurl4", ver: "7.68.0-1ubuntu2.6", rls: "UBUNTU20.04 LTS" ) )){
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

