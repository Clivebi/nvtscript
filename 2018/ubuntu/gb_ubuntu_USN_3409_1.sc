if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843676" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2017-11568", "CVE-2017-11569", "CVE-2017-11572", "CVE-2017-11571", "CVE-2017-11574", "CVE-2017-11575", "CVE-2017-11577", "CVE-2017-11576" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-13 14:23:00 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:05:24 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for fontforge USN-3409-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3409-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3409-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fontforge'
  package(s) announced via the USN-3409-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that FontForge was vulnerable to a heap-based buffer
over-read. A remote attacker could use a crafted file to DoS or execute
arbitrary code. (CVE-2017-11568, CVE-2017-11569, CVE-2017-11572)

It was discovered that FontForge was vulnerable to a stack-based buffer
overflow. A remote attacker could use a crafted file to DoS or execute
arbitrary code. (CVE-2017-11571)

It was discovered that FontForge was vulnerable to a heap-based buffer
overflow. A remote attacker could use a crafted file to DoS or execute
arbitrary code. (CVE-2017-11574)

It was discovered that FontForge was vulnerable to a buffer over-read.
A remote attacker could use a crafted file to DoS or execute arbitrary
code. (CVE-2017-11575, CVE-2017-11577)

It was discovered that FontForge wasn't correctly checking the sign of
a vector size. A remote attacker could use a crafted file to DoS.
(CVE-2017-11576)" );
	script_tag( name: "affected", value: "fontforge on Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "fontforge", ver: "20120731.b-5ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "fontforge-common", ver: "20120731.b-5ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

