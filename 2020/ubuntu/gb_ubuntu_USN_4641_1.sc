if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844726" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2017-15266", "CVE-2017-15267", "CVE-2017-15600", "CVE-2018-16430", "CVE-2018-20430", "CVE-2017-15601", "CVE-2017-15602", "CVE-2017-15922", "CVE-2017-17440", "CVE-2018-14346", "CVE-2018-14347", "CVE-2018-20431" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-25 12:17:00 +0000 (Thu, 25 Oct 2018)" );
	script_tag( name: "creation_date", value: "2020-11-24 04:00:42 +0000 (Tue, 24 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for libextractor (USN-4641-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4641-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005772.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libextractor'
  package(s) announced via the USN-4641-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Libextractor incorrectly handled zero sample rate.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2017-15266)

It was discovered that Libextractor incorrectly handled certain FLAC
metadata. An attacker could possibly use this issue to cause a denial of
service. (CVE-2017-15267)

It was discovered that Libextractor incorrectly handled certain specially
crafted files. An attacker could possibly use this issue to cause a denial
of service. (CVE-2017-15600, CVE-2018-16430, CVE-2018-20430)

It was discovered that Libextractor incorrectly handled certain inputs. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2017-15601)

It was discovered that Libextractor incorrectly handled integers. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2017-15602)

It was discovered that Libextractore incorrectly handled certain crafted
files. An attacker could possibly use this issue to cause a denial of
service. (CVE-2017-15922)

It was discovered that Libextractor incorrectly handled certain files. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2017-17440)

It was discovered that Libextractor incorrectly handled certain malformed
files. An attacker could possibly use this issue to cause a denial of
service. (CVE-2018-14346)

It was discovered that Libextractor incorrectly handled malformed files. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2018-14347)

It was discovered that Libextractor incorrectly handled metadata. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2018-20431)" );
	script_tag( name: "affected", value: "'libextractor' package(s) on Ubuntu 16.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "extract", ver: "1:1.3-4+deb9u3build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libextractor-dev", ver: "1:1.3-4+deb9u3build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libextractor3", ver: "1:1.3-4+deb9u3build0.16.04.1", rls: "UBUNTU16.04 LTS" ) )){
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

