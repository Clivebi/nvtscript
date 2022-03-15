if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844268" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-11755", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-12-11 03:01:29 +0000 (Wed, 11 Dec 2019)" );
	script_name( "Ubuntu Update for thunderbird USN-4202-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU19\\.10|UBUNTU18\\.04 LTS)" );
	script_xref( name: "USN", value: "4202-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-December/005245.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the USN-4202-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4202-1 fixed vulnerabilities in Thunderbird. After upgrading,
Thunderbird
created a new profile for some users. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that a specially crafted S/MIME message with an inner
encryption layer could be displayed as having a valid signature in some
circumstances, even if the signer had no access to the encrypted message.
An attacker could potentially exploit this to spoof the message author.
(CVE-2019-11755)
Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
bypass security restrictions, bypass same-origin restrictions, conduct
cross-site scripting (XSS) attacks, or execute arbitrary code.
(CVE-2019-11757, CVE-2019-11758, CVE-2019-11759, CVE-2019-11760,
CVE-2019-11761, CVE-2019-11762, CVE-2019-11763, CVE-2019-11764)
A heap overflow was discovered in the expat library in Thunderbird. If a
user were tricked in to opening a specially crafted message, an attacker
could potentially exploit this to cause a denial of service, or execute
arbitrary code. (CVE-2019-15903)" );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:68.2.2+build1-0ubuntu0.19.10.1", rls: "UBUNTU19.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:68.2.2+build1-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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

