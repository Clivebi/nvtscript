if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841961" );
	script_version( "2020-01-17T13:03:22+0000" );
	script_tag( name: "last_modification", value: "2020-01-17 13:03:22 +0000 (Fri, 17 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-09-09 05:55:13 +0200 (Tue, 09 Sep 2014)" );
	script_cve_id( "CVE-2013-4357", "CVE-2013-4458", "CVE-2014-0475", "CVE-2014-4043" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for eglibc USN-2306-3" );
	script_tag( name: "insight", value: "USN-2306-1 fixed vulnerabilities in the
GNU C Library. On Ubuntu 10.04 LTS, the fix for CVE-2013-4357 introduced a
memory leak in getaddrinfo. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Maksymilian Arciemowicz discovered that the GNU C Library incorrectly
handled the getaddrinfo() function. An attacker could use this issue to
cause a denial of service. This issue only affected Ubuntu 10.04 LTS.
(CVE-2013-4357)
It was discovered that the GNU C Library incorrectly handled the
getaddrinfo() function. An attacker could use this issue to cause a denial
of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
(CVE-2013-4458)
Stephane Chazelas discovered that the GNU C Library incorrectly handled
locale environment variables. An attacker could use this issue to possibly
bypass certain restrictions such as the ForceCommand restrictions in
OpenSSH. (CVE-2014-0475)
David Reid, Glyph Lefkowitz, and Alex Gaynor discovered that the GNU C
Library incorrectly handled posix_spawn_file_actions_addopen() path
arguments. An attacker could use this issue to cause a denial of service.
(CVE-2014-4043)" );
	script_tag( name: "affected", value: "eglibc on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2306-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2306-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'eglibc'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.11.1-0ubuntu7.17", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

