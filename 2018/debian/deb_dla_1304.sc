if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891304" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18206" );
	script_name( "Debian LTS: Security Advisory for zsh (DLA-1304-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 19:27:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "zsh on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in zsh version
4.3.17-1+deb7u1.

We recommend that you upgrade your zsh packages." );
	script_tag( name: "summary", value: "It was discovered that there were multiple vulnerabilities in the
'zsh' shell:

  * CVE-2014-10070: Fix a privilege-elevation issue if the
environment has not been properly sanitized.

  * CVE-2014-10071: Prevent a buffer overflow for very long file

  * descriptors in the '>& fd' syntax.

  * CVE-2014-10072: Correct a buffer overflow when scanning very long
directory paths for symbolic links.

  * CVE-2016-10714: Fix an off-by-one error that was resulting in
undersized buffers that were intended to support PATH_MAX.

  * CVE-2017-18206: Fix a buffer overflow in symlink expansion." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zsh", ver: "4.3.17-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-dbg", ver: "4.3.17-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-dev", ver: "4.3.17-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-doc", ver: "4.3.17-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zsh-static", ver: "4.3.17-1+deb7u1", rls: "DEB7" ) )){
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

