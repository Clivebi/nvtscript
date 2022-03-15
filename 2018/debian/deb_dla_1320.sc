if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891320" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2018-1050" );
	script_name( "Debian LTS: Security Advisory for samba (DLA-1320-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-28 00:00:00 +0200 (Wed, 28 Mar 2018)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00024.html" );
	script_xref( name: "URL", value: "https://www.samba.org/samba/security/CVE-2018-1050.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "samba on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.6-6+deb7u16.

We recommend that you upgrade your samba packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues:

CVE-2018-1050

    It was discovered that Samba is prone to a denial of service
    attack when the RPC spoolss service is configured to be run as an
    external daemon. Thanks for Jeremy Allison for the patch." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss-winbind", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-smbpass", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-winbind", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsmbclient-dev", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient-dev", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwbclient0", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-common-bin", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-dbg", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-doc", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-doc-pdf", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "samba-tools", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "smbclient", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "swat", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "winbind", ver: "3.6.6-6+deb7u16", rls: "DEB7" ) )){
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

