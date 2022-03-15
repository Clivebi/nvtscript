if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890898" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853" );
	script_name( "Debian LTS: Security Advisory for libosip2 (DLA-898-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00016.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libosip2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.0-4+deb7u1.

We recommend that you upgrade your libosip2 packages." );
	script_tag( name: "summary", value: "CVE-2016-10324
In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to
a heap buffer overflow in the osip_clrncpy() function defined in
osipparser2/osip_port.c.

CVE-2016-10325
In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to a
heap buffer overflow in the _osip_message_to_str() function defined
in osipparser2/osip_message_to_str.c, resulting in a remote DoS.

CVE-2016-10326
In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to
a heap buffer overflow in the osip_body_to_str() function defined
in osipparser2/osip_body.c, resulting in a remote DoS.

CVE-2017-7853
In libosip2 in GNU oSIP 5.0.0, a malformed SIP message can lead to a
heap buffer overflow in the msg_osip_body_parse() function defined
in osipparser2/osip_message_parse.c, resulting in a remote DoS." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libosip2-7", ver: "3.6.0-4+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libosip2-dev", ver: "3.6.0-4+deb7u1", rls: "DEB7" ) )){
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

