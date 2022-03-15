if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891332" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-7225" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-1332-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-02 00:00:00 +0200 (Mon, 02 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00035.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libvncserver on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.9.9+dfsg-1+deb7u3.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "summary", value: "libvncserver version through 0.9.11. does not sanitize msg.cct.length
which may result in access to uninitialized and potentially sensitive
data or possibly unspecified other impact (e.g., an integer overflow)
via specially crafted VNC packets." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg-1+deb7u3", rls: "DEB7" ) )){
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

