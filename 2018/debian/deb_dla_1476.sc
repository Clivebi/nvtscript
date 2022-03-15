if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891476" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-15473", "CVE-2018-15599" );
	script_name( "Debian LTS: Security Advisory for dropbear (DLA-1476-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00026.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "dropbear on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2014.65-1+deb8u3.

We recommend that you upgrade your dropbear packages." );
	script_tag( name: "summary", value: "vulnerability in dropbear, a lightweight SSH2 server and client, making it
possible to guess valid usernames has been found:

CVE-2018-15599:

The recv_msg_userauth_request function in svr-auth.c in is prone
to a user enumeration vulnerability, similar to CVE-2018-15473 in OpenSSH." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dropbear", ver: "2014.65-1+deb8u3", rls: "DEB8" ) )){
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

