if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843475" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-15 08:47:52 +0100 (Thu, 15 Mar 2018)" );
	script_cve_id( "CVE-2018-5125", "CVE-2018-5126", "CVE-2018-5127", "CVE-2018-5128", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5136", "CVE-2018-5137", "CVE-2018-5140", "CVE-2018-5141", "CVE-2018-5142", "CVE-2018-5131", "CVE-2018-5132", "CVE-2018-5134", "CVE-2018-5135", "CVE-2018-5133", "CVE-2018-5143" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-06 17:57:00 +0000 (Mon, 06 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-3596-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in
  Firefox. If a user were tricked in to opening a specially crafted website, an
  attacker could potentially exploit these to cause a denial of service via
  application crash or opening new tabs, escape the sandbox, bypass same-origin
  restrictions, obtain sensitive information, confuse the user with misleading
  permission requests, or execute arbitrary code. (CVE-2018-5125, CVE-2018-5126,
  CVE-2018-5127, CVE-2018-5128, CVE-2018-5129, CVE-2018-5130, CVE-2018-5136,
  CVE-2018-5137, CVE-2018-5140, CVE-2018-5141, CVE-2018-5142) It was discovered
  that the fetch() API could incorrectly return cached copies of no-store/no-cache
  resources in some circumstances. A local attacker could potentially exploit this
  to obtain sensitive information in environments where multiple users share a
  common profile. (CVE-2018-5131) Multiple security issues were discovered with
  WebExtensions. If a user were tricked in to installing a specially crafted
  extension, an attacker could potentially exploit these to obtain sensitive
  information or bypass security restrictions. (CVE-2018-5132, CVE-2018-5134,
  CVE-2018-5135) It was discovered that the value of app.support.baseURL is not
  sanitized properly. If a malicious local application were to set this to a
  specially crafted value, an attacker could potentially exploit this to execute
  arbitrary code. (CVE-2018-5133) It was discovered that javascript: URLs with
  embedded tab characters could be pasted in to the addressbar. If a user were
  tricked in to copying a specially crafted URL in to the addressbar, an attacker
  could exploit this to conduct cross-site scripting (XSS) attacks.
  (CVE-2018-5143)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 17.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3596-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3596-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "59.0+build5-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "59.0+build5-0ubuntu0.17.10.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "59.0+build5-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

