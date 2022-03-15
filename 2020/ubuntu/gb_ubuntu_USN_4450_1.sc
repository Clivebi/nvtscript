if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844528" );
	script_version( "2021-07-12T11:00:45+0000" );
	script_cve_id( "CVE-2020-11937", "CVE-2020-12135", "CVE-2020-15570" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 11:00:45 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-12 17:15:00 +0000 (Wed, 12 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-05 03:00:35 +0000 (Wed, 05 Aug 2020)" );
	script_name( "Ubuntu: Security Advisory for whoopsie (USN-4450-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4450-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005546.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'whoopsie'
  package(s) announced via the USN-4450-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Seong-Joong Kim discovered that Whoopsie incorrectly handled memory. A
local attacker could use this issue to cause Whoopsie to consume memory,
resulting in a denial of service. (CVE-2020-11937)

Seong-Joong Kim discovered that Whoopsie incorrectly handled parsing files.
A local attacker could use this issue to cause Whoopsie to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2020-12135)

Seong-Joong Kim discovered that Whoopsie incorrectly handled memory. A
local attacker could use this issue to cause Whoopsie to consume memory,
resulting in a denial of service. (CVE-2020-15570)" );
	script_tag( name: "affected", value: "'whoopsie' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libwhoopsie0", ver: "0.2.62ubuntu0.5", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "whoopsie", ver: "0.2.62ubuntu0.5", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libwhoopsie0", ver: "0.2.52.5ubuntu0.5", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "whoopsie", ver: "0.2.52.5ubuntu0.5", rls: "UBUNTU16.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libwhoopsie0", ver: "0.2.69ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "whoopsie", ver: "0.2.69ubuntu0.1", rls: "UBUNTU20.04 LTS" ) )){
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

