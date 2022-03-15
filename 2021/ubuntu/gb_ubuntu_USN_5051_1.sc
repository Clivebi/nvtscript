if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845033" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-3711", "CVE-2021-3712" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-25 03:00:36 +0000 (Wed, 25 Aug 2021)" );
	script_name( "Ubuntu: Security Advisory for openssl (USN-5051-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5051-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-August/006152.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the USN-5051-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "John Ouyang discovered that OpenSSL incorrectly handled decrypting SM2
data. A remote attacker could use this issue to cause applications using
OpenSSL to crash, resulting in a denial of service, or possibly change
application behaviour. (CVE-2021-3711)

Ingo Schwarze discovered that OpenSSL incorrectly handled certain ASN.1
strings. A remote attacker could use this issue to cause OpenSSL to crash,
resulting in a denial of service, or possibly obtain sensitive information.
(CVE-2021-3712)" );
	script_tag( name: "affected", value: "'openssl' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1-1ubuntu2.1~18.04.13", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1f-1ubuntu2.8", rls: "UBUNTU20.04 LTS" ) )){
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

