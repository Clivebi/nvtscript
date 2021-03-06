if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841592" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-18 09:16:08 +0530 (Fri, 18 Oct 2013)" );
	script_cve_id( "CVE-2013-0900", "CVE-2013-2924" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for icu USN-1989-1" );
	script_tag( name: "affected", value: "icu on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that ICU contained a race condition affecting multi-
threaded applications. If an application using ICU processed crafted data,
an attacker could cause it to crash or potentially execute arbitrary code
with the privileges of the user invoking the program. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 12.10. (CVE-2013-0900)

It was discovered that ICU incorrectly handled memory operations. If an
application using ICU processed crafted data, an attacker could cause it to
crash or potentially execute arbitrary code with the privileges of the user
invoking the program. (CVE-2013-2924)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1989-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1989-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libicu48", ver: "4.8.1.1-3ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libicu48", ver: "4.8.1.1-8ubuntu0.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libicu48", ver: "4.8.1.1-12ubuntu0.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

