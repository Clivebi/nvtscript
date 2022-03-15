if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842393" );
	script_version( "2020-01-28T08:10:01+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 08:10:01 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-07-30 05:15:02 +0200 (Thu, 30 Jul 2015)" );
	script_cve_id( "CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-3210", "CVE-2015-5073" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for pcre3 USN-2694-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pcre3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Michele Spagnuolo discovered that PCRE
incorrectly handled certain regular expressions. A remote attacker could use this
issue to cause applications using PCRE to crash, resulting in a denial of service,
or possibly execute arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-8964)

Kai Lu discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04.
(CVE-2015-2325, CVE-2015-2326)

Wen Guanxing discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 15.04. (CVE-2015-3210)

It was discovered that PCRE incorrectly handled certain regular
expressions. A remote attacker could use this issue to cause applications
using PCRE to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS and 14.04 LTS.
(CVE-2015-5073)" );
	script_tag( name: "affected", value: "pcre3 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2694-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2694-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libpcre3:amd64", ver: "1:8.31-2ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpcre3:i386", ver: "1:8.31-2ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpcre3", ver: "8.12-4ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

