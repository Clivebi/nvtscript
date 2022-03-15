if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844332" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2019-16865", "CVE-2019-19911", "CVE-2020-5312", "CVE-2020-5310", "CVE-2020-5311", "CVE-2020-5313" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-02-07 04:00:18 +0000 (Fri, 07 Feb 2020)" );
	script_name( "Ubuntu: Security Advisory for pillow (USN-4272-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4272-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-February/005320.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pillow'
  package(s) announced via the USN-4272-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Pillow incorrectly handled certain images.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2019-16865, CVE-2019-19911)

It was discovered that Pillow incorrectly handled certain images.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2020-5312)

It was discovered that Pillow incorrectly handled certain TIFF images.
An attacker could possibly use this issue to cause a crash. This issue
only affected Ubuntu 19.10. (CVE-2020-5310)

It was discovered that Pillow incorrectly handled certain SGI images.
An attacker could possibly use this issue to execute arbitrary code or
cause a crash. This issue only affected Ubuntu 18.04 and Ubuntu 19.10.
(CVE-2020-5311)

It was discovered that Pillow incorrectly handled certain PCX images.
An attackter could possibly use this issue to execute arbitrary code or
cause a crash. (CVE-2020-5312)

It was discovered that Pillow incorrectly handled certain Flip images.
An attacker could possibly use this issue to execute arbitrary code or
cause a crash. (CVE-2020-5313)" );
	script_tag( name: "affected", value: "'pillow' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "python-pil", ver: "6.1.0-1ubuntu0.2", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "6.1.0-1ubuntu0.2", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-pil", ver: "5.1.0-1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "5.1.0-1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "python-imaging", ver: "3.1.2-0ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python-pil", ver: "3.1.2-0ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "python3-pil", ver: "3.1.2-0ubuntu1.3", rls: "UBUNTU16.04 LTS" ) )){
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

