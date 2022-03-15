if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704280" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-15473" );
	script_name( "Debian Security Advisory DSA 4280-1 (openssh - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-22 00:00:00 +0200 (Wed, 22 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4280.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openssh on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1:7.4p1-10+deb9u4.

We recommend that you upgrade your openssh packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openssh" );
	script_tag( name: "summary", value: "Dariusz Tytko, Michal Sajdak and Qualys Security discovered that
OpenSSH, an implementation of the SSH protocol suite, was prone to a
user enumeration vulnerability. This would allow a remote attacker to
check whether a specific user account existed on the target server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openssh-client", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssh-client-ssh1", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssh-server", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssh-sftp-server", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ssh", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ssh-askpass-gnome", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ssh-krb5", ver: "1:7.4p1-10+deb9u4", rls: "DEB9" ) )){
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

