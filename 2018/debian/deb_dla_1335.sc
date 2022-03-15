if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891335" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2018-1071", "CVE-2018-1083" );
	script_name( "Debian LTS: Security Advisory for zsh (DLA-1335-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-01 07:15:00 +0000 (Tue, 01 Dec 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00038.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "zsh on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.3.17-1+deb7u2.

We recommend that you upgrade your zsh packages." );
	script_tag( name: "summary", value: "Two security vulnerabilities were discovered in the Z shell.

CVE-2018-1071
Stack-based buffer overflow in the exec.c:hashcmd() function.
A local attacker could exploit this to cause a denial of service.

CVE-2018-1083
Buffer overflow in the shell autocomplete functionality. A local
unprivileged user can create a specially crafted directory path which
leads to code execution in the context of the user who tries to use
autocomplete to traverse the before mentioned path. If the user
affected is privileged, this leads to privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zsh", ver: "4.3.17-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-dbg", ver: "4.3.17-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-dev", ver: "4.3.17-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-doc", ver: "4.3.17-1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-static", ver: "4.3.17-1+deb7u2", rls: "DEB7" ) )){
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

