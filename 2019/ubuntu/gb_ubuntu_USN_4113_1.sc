if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844154" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2019-0197", "CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098", "CVE-2019-9517" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-08-30 02:00:40 +0000 (Fri, 30 Aug 2019)" );
	script_name( "Ubuntu Update for apache2 USN-4113-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4113-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-August/005090.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2'
  package(s) announced via the USN-4113-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stefan Eissing discovered that the HTTP/2 implementation in Apache
did not properly handle upgrade requests from HTTP/1.1 to HTTP/2 in
some situations. A remote attacker could use this to cause a denial
of service (daemon crash). This issue only affected Ubuntu 18.04 LTS
and Ubuntu 19.04. (CVE-2019-0197)

Craig Young discovered that a memory overwrite error existed in
Apache when performing HTTP/2 very early pushes in some situations. A
remote attacker could use this to cause a denial of service (daemon
crash). This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04.
(CVE-2019-10081)

Craig Young discovered that a read-after-free error existed in the
HTTP/2 implementation in Apache during connection shutdown. A remote
attacker could use this to possibly cause a denial of service (daemon
crash) or possibly expose sensitive information. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-10082)

Matei Badanoiu discovered that the mod_proxy component of
Apache did not properly filter URLs when reporting errors in some
configurations. A remote attacker could possibly use this issue to
conduct cross-site scripting (XSS) attacks. (CVE-2019-10092)

Daniel McCarney discovered that mod_remoteip component of Apache
contained a stack buffer overflow when parsing headers from a trusted
intermediary proxy in some situations. A remote attacker controlling a
trusted proxy could use this to cause a denial of service or possibly
execute arbitrary code. This issue only affected Ubuntu 19.04.
(CVE-2019-10097)

Yukitsugu Sasaki discovered that the mod_rewrite component in Apache
was vulnerable to open redirects in some situations. A remote attacker
could use this to possibly expose sensitive information or bypass
intended restrictions. (CVE-2019-10098)

Jonathan Looney discovered that the HTTP/2 implementation in Apache did
not properly limit the amount of buffering for client connections in
some situations. A remote attacker could use this to cause a denial
of service (unresponsive daemon). This issue only affected Ubuntu
18.04 LTS and Ubuntu 19.04. (CVE-2019-9517)" );
	script_tag( name: "affected", value: "'apache2' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "apache2", ver: "2.4.29-1ubuntu4.10", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.29-1ubuntu4.10", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apache2", ver: "2.4.38-2ubuntu2.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.38-2ubuntu2.2", rls: "UBUNTU19.04" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "apache2", ver: "2.4.18-2ubuntu3.12", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.18-2ubuntu3.12", rls: "UBUNTU16.04 LTS" ) )){
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

