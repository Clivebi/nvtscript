if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842995" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-12-20 05:42:07 +0100 (Tue, 20 Dec 2016)" );
	script_cve_id( "CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-3158-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Frederic Besler and others discovered that
  the ndr_pull_dnsp_nam function in Samba contained an integer overflow. An
  authenticated attacker could use this to gain administrative privileges. This
  issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10.
(CVE-2016-2123)

Simo Sorce discovered that Samba clients always requested
a forwardable ticket when using Kerberos authentication. An
attacker could use this to impersonate an authenticated user or
service. (CVE-2016-2125)

Volker Lendecke discovered that Kerberos PAC validation implementation
in Samba contained multiple vulnerabilities. An authenticated attacker
could use this to cause a denial of service or gain administrative
privileges. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
LTS, and Ubuntu 16.10. (CVE-2016-2126)" );
	script_tag( name: "affected", value: "samba on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3158-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3158-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.3.11+dfsg-0ubuntu0.14.04.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.4.5+dfsg-2ubuntu5.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.4.5+dfsg-2ubuntu5.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.4.5+dfsg-2ubuntu5.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:3.6.25-0ubuntu0.12.04.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.25-0ubuntu0.12.04.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsmbclient", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "winbind", ver: "2:4.3.11+dfsg-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

