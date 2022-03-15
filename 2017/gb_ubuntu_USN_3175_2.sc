if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843043" );
	script_version( "2021-09-09T10:36:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:36:38 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-07 05:45:17 +0100 (Tue, 07 Feb 2017)" );
	script_cve_id( "CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5393", "CVE-2017-5396" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-02 19:34:00 +0000 (Thu, 02 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-3175-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3175-1 fixed vulnerabilities in Firefox.
  The update caused a regression on systems where the AppArmor profile for Firefox
  is set to enforce mode. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Multiple memory safety issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2017-5373, CVE-2017-5374)

JIT code allocation can allow a bypass of ASLR protections in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2017-5375)

Nicolas Gr&#233 goire discovered a use-after-free when manipulating XSL in
XSLT documents in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2017-5376)

Atte Kettunen discovered a memory corruption issue in Skia in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2017-5377)

Jann Horn discovered that an object's address could be discovered through
hashed codes of JavaScript objects shared between pages. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2017-5378)

A use-after-free was discovered in Web Animations in some circumstances.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2017-5379)

A use-after-free was discovered during DOM manipulation of SVG content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2017-5380)

Jann Horn discovered that the 'export' function in the Certificate Viewer
can force local filesystem navigation when the Common Name contains
slashes. If a user were tricked in to exporting a specially crafted
certificate, an attacker could potentially exploit this to save content
with arbi ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "firefox on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3175-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3175-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "51.0.1+build2-0ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "51.0.1+build2-0ubuntu0.16.10.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "51.0.1+build2-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "51.0.1+build2-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

