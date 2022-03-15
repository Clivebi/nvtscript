if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891567" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-18718" );
	script_name( "Debian LTS: Security Advisory for gthumb (DLA-1567-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-06 00:00:00 +0100 (Tue, 06 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-07 20:29:00 +0000 (Fri, 07 Dec 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00002.html" );
	script_xref( name: "URL", value: "https://gitlab.gnome.org/GNOME/gthumb/issues/18" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gthumb on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3:3.3.1-2.1+deb8u1

We recommend that you upgrade your gthumb packages." );
	script_tag( name: "summary", value: "CVE-2018-18718 - CWE-415: Double Free
The product calls free() twice on the same memory address, potentially
leading to modification of unexpected memory locations.

There is a suspected double-free bug with
static void add_themes_from_dir() dlg-contact-sheet.c. This method
involves two successive calls of g_free(buffer) (line 354 and 373),
and is likely to cause double-free of the buffer. One possible fix
could be directly assigning the buffer to NULL after the first call
of g_free(buffer)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gthumb", ver: "3:3.3.1-2.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-data", ver: "3:3.3.1-2.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-dbg", ver: "3:3.3.1-2.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-dev", ver: "3:3.3.1-2.1+deb8u1", rls: "DEB8" ) )){
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

