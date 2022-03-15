if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891089" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-10965", "CVE-2017-10966" );
	script_name( "Debian LTS: Security Advisory for irssi (DLA-1089-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-05 01:29:00 +0000 (Sun, 05 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "irssi on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.8.15-5+deb7u3.

We recommend that you upgrade your irssi packages." );
	script_tag( name: "summary", value: "Some Irssi issues were found:

CVE-2017-10965

An issue was discovered in Irssi before 1.0.4. When receiving messages with
invalid time stamps, Irssi would try to dereference a NULL pointer.

CVE-2017-10966

An issue was discovered in Irssi before 1.0.4. While updating the internal
nick list, Irssi could incorrectly use the GHashTable interface and free
the nick while updating it. This would then result in use-after-free
conditions on each access of the hash table." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "irssi", ver: "0.8.15-5+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "irssi-dev", ver: "0.8.15-5+deb7u3", rls: "DEB7" ) )){
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

