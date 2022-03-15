if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843703" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2013-7459" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:08:49 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for python-crypto USN-3199-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3199-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3199-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-crypto'
  package(s) announced via the USN-3199-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3199-1 fixed a vulnerability in the Python Cryptography Toolkit.
Unfortunately, various programs depended on the original behavior of the Python
Cryptography Toolkit which was altered when fixing the vulnerability. This
update retains the fix for the vulnerability but issues a warning rather than
throwing an exception. Code which produces this warning should be updated
because future versions of the Python Cryptography Toolkit re-introduce the
exception.

We apologize for the inconvenience.

Original advisory details:

&#160 It was discovered that the ALGnew function in block_template.c in the Python
&#160 Cryptography Toolkit contained a heap-based buffer overflow vulnerability.
&#160 A remote attacker could use this flaw to execute arbitrary code by using
&#160 a crafted initialization vector parameter." );
	script_tag( name: "affected", value: "python-crypto on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
	if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.6.1-4ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-crypto", ver: "2.6.1-4ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.6.1-6ubuntu0.16.10.3", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-crypto", ver: "2.6.1-6ubuntu0.16.10.3", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-crypto", ver: "2.6.1-6ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-crypto", ver: "2.6.1-6ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

