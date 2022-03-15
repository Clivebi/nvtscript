if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842401" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-05 05:08:52 +0200 (Wed, 05 Aug 2015)" );
	script_cve_id( "CVE-2015-1270", "CVE-2015-1272", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1287", "CVE-2015-1289", "CVE-2015-1329", "CVE-2015-5605" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for oxide-qt USN-2677-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An uninitialized value issue was discovered
in ICU. If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service.
(CVE-2015-1270)

A use-after-free was discovered in the GPU process implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1272)

A use-after-free was discovered in the IndexedDB implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1276)

A use-after-free was discovered in the accessibility implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1277)

A memory corruption issue was discovered in Skia. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2015-1280)

It was discovered that Blink did not properly determine the V8 context of
a microtask in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass Content Security Policy (CSP) restrictions. (CVE-2015-1281)

Multiple integer overflows were discovered in Expat. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
the program. (CVE-2015-1283)

It was discovered that Blink did not enforce a page's maximum number of
frames in some circumstances, resulting in a use-after-free. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer crash,
or execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1284)

It was discovered that the XSS auditor in Blink did not properly choose a
truncation point. If a user were tricked in to open ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "oxide-qt on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2677-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2677-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:amd64", ver: "1.8.4-0ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "liboxideqtcore0:i386", ver: "1.8.4-0ubuntu0.14.04.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

